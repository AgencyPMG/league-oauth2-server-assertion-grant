<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Jwt;

use DateTimeImmutable;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory as JwtKey;
use Lcobucci\JWT\Signer\Rsa\Sha384;
use Lcobucci\JWT\Token\Parser as DefaultParser;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint as JwtConstraint;
use Lcobucci\JWT\Validation\Validator;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PMG\AssertionGrant\Assertion;
use PMG\AssertionGrant\AssertionGrantBackend;
use PMG\AssertionGrant\AssertionRequest;
use PMG\AssertionGrant\DefaultAssertion;
use PMG\AssertionGrant\Jwt\Constraint\HasStringClaim;
use PMG\AssertionGrant\Jwt\Constraint\HasValidExpiration;
use PMG\AssertionGrant\Jwt\Exception\InvalidJwt;
use PMG\AssertionGrant\Jwt\Exception\InvalidKeyId;
use PMG\AssertionGrant\Jwt\Exception\AssertionKeyNotFound;
use PMG\AssertionGrant\Jwt\Exception\CannotIssueAccessToken;
use PMG\AssertionGrant\Jwt\Exception\InvalidAssertion;

/**
 * An implementation of the `urn:ietf:params:oauth:grant-type:jwt-bearer`
 * grant type from RFC 7523.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7523
 */
final class JwtAssertionGrantBackend implements AssertionGrantBackend
{
    public const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    public const PARAM_ASSERTION = 'assertion';
    public const HEADER_KEY_ID = 'kid';

    private AssertionKeyRepository $assertionKeyRepository;

    private Signer $jwtSigner;

    private ?AssertionRepository $assertionRepository;

    private Parser $jwtParser;

    private Clock $clock;

    public function __construct(
        AssertionKeyRepository $assertionKeyRepository,
        ?Signer $jwtSigner=null,
        ?AssertionRepository $assertionRepository=null,
        ?Parser $jwtParser=null,
        ?Clock $clock=null,
    ) {
        $this->assertionKeyRepository = $assertionKeyRepository;
        $this->jwtSigner = $jwtSigner ?? new Sha384();
        $this->assertionRepository = $assertionRepository;
        $this->jwtParser = $jwtParser ?? new DefaultParser(new JoseEncoder());
        $this->clock = $clock ?? SystemClock::fromSystemTimezone();
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType() : string
    {
        return self::GRANT_TYPE;
    }

    /**
     * {@inheritdoc}
     */
    public function parseAndValidate(AssertionRequest $request) : Assertion
    {
        $assertion = $this->parseJwtAssertion($request->getAssertion());

        $key = $this->getKey($assertion);

        $this->validateAssertion($request, $assertion, $key);

        $this->maybeCheckForReplay($assertion);
        $claims = $assertion->claims();

        $issuer = $claims->get(RegisteredClaims::ISSUER);
        assert(is_string($issuer) && $issuer !== '');

        $subject = $claims->get(RegisteredClaims::SUBJECT);
        assert(is_string($subject) && $subject !== '');

        $expiresAt = $claims->get(RegisteredClaims::EXPIRATION_TIME);
        assert($expiresAt instanceof DateTimeImmutable);

        $issuedAt = $claims->get(RegisteredClaims::ISSUED_AT);
        assert(null === $issuedAt || $issuedAt instanceof DateTimeImmutable);

        $result = new DefaultAssertion(
            $issuer,
            $subject,
            $request->getExpectedAudience(),
            $expiresAt,
            $issuedAt,
            $key->getAllowedScopes()
        );

        if (!$key->canIssueAccessTokenTo($result)) {
            throw CannotIssueAccessToken::to($key, $result);
        }

        return $result;
    }

    /**
     * Run the assertion through validation, this includes signature verification
     * as well as making sure we have the correct claims, etc.
     *
     * @throws InvalidAssertion if anything is wrong with the assertion
     */
    private function validateAssertion(
        AssertionRequest $request,
        UnencryptedToken $assertion,
        AssertionKey $key,
    ) : void {
        $constraints = [
            new JwtConstraint\SignedWith(
                $this->jwtSigner,
                JwtKey::plainText($key->getSigningKey())
            ),
            new HasValidExpiration($this->clock, $request->getAccessTokenTtl()),
            new JwtConstraint\LooseValidAt($this->clock),
            new JwtConstraint\PermittedFor($request->getExpectedAudience()),
            new HasStringClaim(RegisteredClaims::SUBJECT),
        ];

        if ($request->getExpectedIssuer() !== null && $request->getExpectedIssuer() !== '') {
            $constraints[] = new JwtConstraint\IssuedBy($request->getExpectedIssuer());
        } else {
            $constraints[] = new HasStringClaim(RegisteredClaims::ISSUER);
        }

        // if we are tracking assertions via ID, then make sure the ID is present
        if ($this->assertionRepository instanceof AssertionRepository) {
            $constraints[] = new HasStringClaim(RegisteredClaims::ID);
        }

        try {
            (new Validator())->assert($assertion, ...$constraints);
        } catch (RequiredConstraintsViolated $e) {
            throw InvalidAssertion::wrap($e);
        }
    }

    /**
     * if an assertion repository was given to the constructor, a jti claim
     * will have been validated agove and this method will check that JTI
     * to see if it has been seen before.
     */
    private function maybeCheckForReplay(UnencryptedToken $assertion) : void
    {
        if (!$this->assertionRepository instanceof AssertionRepository) {
            return;
        }

        $assertionId = $assertion->claims()->get(RegisteredClaims::ID);
        assert(is_string($assertionId)); // validated above

        if ($this->assertionRepository->isAssertionReplay($assertionId)) {
            throw InvalidAssertion::replay($assertionId);
        }

        $expiresAt = $assertion->claims()->get(RegisteredClaims::EXPIRATION_TIME);
        assert($expiresAt instanceof DateTimeImmutable);

        $this->assertionRepository->persistNewAssertion($assertionId, $expiresAt);
    }

    /**
     * Pull the `assertion` parameter out of the request and parse it as the
     * JWT its meant to be.
     *
     * @param non-empty-string $assertion
     */
    private function parseJwtAssertion(string $assertion) : UnencryptedToken
    {
        try {
            $assertionToken = $this->jwtParser->parse($assertion);
        } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $e) {
            throw InvalidJwt::wrap($e);
        }

        assert($assertionToken instanceof UnencryptedToken);

        return $assertionToken;
    }

    /**
     * Extract the key ID header from the assertion and look up the key.
     *
     * @throws AssertionKeyNotFound if the key ID cannot be found
     */
    private function getKey(UnencryptedToken $assertion) : AssertionKey
    {
        $keyId = $this->getKeyId($assertion);

        $key = $this->assertionKeyRepository->getAssertionKeyById($keyId);
        if (null === $key) {
            throw AssertionKeyNotFound::with($keyId);
        }

        return $key;
    }

    /**
     * Extract the key id from the assertion header and return it
     *
     * @throws InvalidKeyId if the header is missing or malformed
     */
    private function getKeyId(UnencryptedToken $assertion) : string
    {
        $keyId = $assertion->headers()->get(self::HEADER_KEY_ID);
        if (!$keyId) {
            throw InvalidKeyId::missing();
        }

        if (!is_string($keyId)) {
            throw InvalidKeyId::invalidType($keyId);
        }

        return $keyId;
    }
}
