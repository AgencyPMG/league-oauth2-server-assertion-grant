<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Test\Jwt;

use DateTimeImmutable;
use DateInterval;
use OpenSSLAsymmetricKey;
use Laminas\Diactoros\ServerRequest;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\MockObject\MockObject;
use PMG\AssertionGrant\Assertion;
use PMG\AssertionGrant\AssertionRequest;
use PMG\AssertionGrant\Jwt\AssertionRepository;
use PMG\AssertionGrant\Jwt\AssertionKey;
use PMG\AssertionGrant\Jwt\AssertionKeyRepository;
use PMG\AssertionGrant\Jwt\JwtAssertionGrantBackend;
use PMG\AssertionGrant\Jwt\Exception\AssertionKeyNotFound;
use PMG\AssertionGrant\Jwt\Exception\CannotIssueAccessToken;
use PMG\AssertionGrant\Jwt\Exception\InvalidAssertion;
use PMG\AssertionGrant\Jwt\Exception\InvalidJwt;
use PMG\AssertionGrant\Jwt\Exception\InvalidKeyId;

/**
 * Tests all the ways an assertion can fail validation
 */
class JwtAssertionGrantBackendTest extends JwtTestCase
{
    protected const AUDIENCE = 'https://oauth.example.com';
    protected const NOW = '2022-11-14 00:00:00';
    protected const KEY_ID = 'faada50c-5734-4806-ac7e-161b538af489';
    protected const OAUTH_CLIENT_ID = '46ac7fe4-3a8d-4207-8985-05143c46b1e3';
    protected const USER_ID = '0366b753-cb52-4460-99eb-a855ef61a864';
    protected const ASSERTION_ID = 'c760c348-2c3f-4e77-98d9-003c20efbe29';
    protected const SCOPES = ['test_scope'];

    protected Configuration $jwtConfig;
    protected DateTimeImmutable $now;
    protected FrozenClock $clock;

    /**
     * @var AssertionKeyRepository&MockObject
     */
    protected AssertionKeyRepository $assertionKeyRepository;

    /**
     * @var AssertionRepository&MockObject
     */
    protected AssertionRepository $assertionRepository;

    protected JwtAssertionGrantBackend $backend;

    protected DateInterval $accessTokenTtl;

    public function testGrantTypeIsJwtBearer() : void
    {
        $this->assertSame(
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
            $this->backend->getGrantType()
        );
    }

    /**
     * @return iterable<string[]>
     */
    public function malformedJwt() : iterable
    {
        yield 'not enough dots' => ['a.b'];

        yield 'invalid encoding' => ['not base.64.here'];
    }

    /**
     * @dataProvider malformedJwt
     */
    public function testMalformedJwtAssertionJwtCausesErrors(string $assertion) : void
    {
        $this->expectException(InvalidJwt::class);

        $this->backend->parseAndValidate($this->assertionRequest($assertion));
    }

    public function testEncryptedJwtIsNotSupported() : void
    {
        $this->expectException(InvalidJwt::class);
        $this->expectExceptionMessage('Encryption is not supported yet');

        $assertion = $this->jwtConfig->builder()
            ->withHeader('enc', 'ignored')
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->backend->parseAndValidate($this->assertionRequest($assertion->toString()));
    }

    public function testAssertionsWithoutKeyIdHeaderCauseErrors() : void
    {
        $this->expectException(InvalidKeyId::class);
        $this->expectExceptionMessage('does not have a `kid` header');

        $assertion = $this->jwtConfig->builder()
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->backend->parseAndValidate($this->assertionRequest($assertion->toString()));
    }

    public function testAssertionsWithNonStringKeyIdsCauseErrors() : void
    {
        $this->expectException(InvalidKeyId::class);
        $this->expectExceptionMessage('`kid` header must be a string');

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, true)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->backend->parseAndValidate($this->assertionRequest($assertion->toString()));
    }

    public function testKeyIdNotFoundCausesError() : void
    {
        $this->expectException(AssertionKeyNotFound::class);

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );
        $this->assertionKeyRepository->expects($this->once())
            ->method('getAssertionKeyById')
            ->with(self::KEY_ID)
            ->willReturn(null);

        $this->backend->parseAndValidate($this->assertionRequest($assertion->toString()));
    }

    public function testInvalidSignatureCausesValidationFailure() : void
    {
        $this->willFindAssertionKey();

        $key = openssl_pkey_new();
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $worked = openssl_pkey_export($key, $keyString);
        $this->assertTrue($worked);

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                InMemory::plainText($keyString)
            );

        $this->checkAssertionFailure($assertion->toString(), 'token signature mismatch');
    }

    public function testMissingAudienceCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'token is not allowed to be used by this audience'
        );
    }

    public function testAudienceMismatchCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(__FUNCTION__)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'token is not allowed to be used by this audience'
        );
    }

    public function testMissingExpirationCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'expiration time is missing or too far in the future',
        );
    }

    public function testExpirationBeyondTokenTtlCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->expiresAt($this->now->add($this->accessTokenTtl)->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'expiration time is missing or too far in the future',
        );
    }

    public function testTokenNotCurrentlyValidCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->canOnlyBeUsedAfter($this->now->add($this->accessTokenTtl))
            ->expiresAt($this->now->add($this->accessTokenTtl)->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'the token cannot be used yet'
        );
    }

    public function testTokensCannotBeIssuedInTheFuture() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->issuedAt($this->now->add($this->accessTokenTtl))
            ->expiresAt($this->now->add($this->accessTokenTtl)->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'the token was issued in the future'
        );
    }

    public function testMissingIssuerCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'iss claim is missing',
        );
    }

    public function testIssuedOtherThanOAuthClientIdCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->issuedBy(__FUNCTION__)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'token was not issued by the given issuers',
            self::OAUTH_CLIENT_ID,
        );
    }

    public function testMissingSubjectCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'sub claim is missing',
        );
    }

    public function testMissingAssertionIdCausesError() : void
    {
        $this->willFindAssertionKey();

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->checkAssertionFailure(
            $assertion->toString(),
            'jti claim is missing',
        );
    }

    public function testReplayedAssertionsCauseErrors() : void
    {
        $this->expectException(InvalidAssertion::class);
        $this->expectExceptionMessage(self::ASSERTION_ID.' has already been used');

        $this->willFindAssertionKey();
        $this->assertionRepository->expects($this->once())
            ->method('isAssertionReplay')
            ->with(self::ASSERTION_ID)
            ->willReturn(true);
        $this->assertionRepository->expects($this->never())
            ->method('persistNewAssertion');

        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );

        $this->backend->parseAndValidate($this->assertionRequest($assertion->toString()));
    }

    public function testKeyCanDeclineToIssueAccesstoken() : void
    {
        $this->expectException(CannotIssueAccessToken::class);

        $key = $this->willFindAssertionKey();
        $assertion = $this->validAssertion();
        $key->expects($this->once())
            ->method('canIssueAccessTokenTo')
            ->with($this->callback(function (Assertion $assertion) : bool {
                $this->assertSame(self::OAUTH_CLIENT_ID, $assertion->getIssuer());
                $this->assertSame(self::USER_ID, $assertion->getSubject());
                return true;
            }))
            ->willReturn(false);

        $this->backend->parseAndValidate($this->assertionRequest($assertion->toString()));
    }

    public function testBackendReturnsAssionObjectWithValuesFromJwtWhenSuccessful() : void
    {
        $key = $this->willFindAssertionKey();
        $assertion = $this->validAssertion();
        $key->expects($this->once())
            ->method('canIssueAccessTokenTo')
            ->with($this->callback(function (Assertion $assertion) : bool {
                $this->assertSame(self::OAUTH_CLIENT_ID, $assertion->getIssuer());
                $this->assertSame(self::USER_ID, $assertion->getSubject());
                return true;
            }))
            ->willReturn(true);
        $key->expects($this->once())
            ->method('getAllowedScopes')
            ->willReturn(self::SCOPES);
        $this->assertionRepository->expects($this->once())
            ->method('isAssertionReplay')
            ->with(self::ASSERTION_ID)
            ->willReturn(false);
        $this->assertionRepository->expects($this->once())
            ->method('persistNewAssertion')
            ->with(self::ASSERTION_ID, $assertion->claims()->get(RegisteredClaims::EXPIRATION_TIME));

        $result = $this->backend->parseAndValidate($this->assertionRequest($assertion->toString()));

        $this->assertSame(self::OAUTH_CLIENT_ID, $result->getIssuer());
        $this->assertSame(self::USER_ID, $result->getSubject());
        $this->assertSame(self::AUDIENCE, $result->getAudience());
        $this->assertEquals(
            $assertion->claims()->get(RegisteredClaims::EXPIRATION_TIME),
            $result->getExpiresAt()
        );
        $this->assertNull($result->getIssuedAt());
        $this->assertSame(self::SCOPES, $result->getAllowedScopes());
    }

    public function testBackendWorksAsExpectedWithoutAssertionRepository() : void
    {
        $this->backend = new JwtAssertionGrantBackend(
            $this->assertionKeyRepository,
            $this->jwtConfig->signer(),
            null,
            $this->jwtConfig->parser(),
            $this->clock
        );

        $key = $this->willFindAssertionKey();
        $assertion = $this->validAssertion();
        $key->expects($this->once())
            ->method('canIssueAccessTokenTo')
            ->with($this->callback(function (Assertion $assertion) : bool {
                $this->assertSame(self::OAUTH_CLIENT_ID, $assertion->getIssuer());
                $this->assertSame(self::USER_ID, $assertion->getSubject());
                return true;
            }))
            ->willReturn(true);
        $key->expects($this->once())
            ->method('getAllowedScopes')
            ->willReturn(self::SCOPES);

        $result = $this->backend->parseAndValidate($this->assertionRequest($assertion->toString()));

        $this->assertSame(self::OAUTH_CLIENT_ID, $result->getIssuer());
        $this->assertSame(self::USER_ID, $result->getSubject());
        $this->assertSame(self::AUDIENCE, $result->getAudience());
        $this->assertEquals(
            $assertion->claims()->get(RegisteredClaims::EXPIRATION_TIME),
            $result->getExpiresAt()
        );
        $this->assertNull($result->getIssuedAt());
        $this->assertSame(self::SCOPES, $result->getAllowedScopes());
    }

    protected function setUp() : void
    {
        $this->jwtConfig = self::createJwtConfiguration();
        $this->now = new DateTimeImmutable(self::NOW);
        $this->clock = new FrozenClock($this->now);
        $this->assertionKeyRepository = $this->createMock(AssertionKeyRepository::class);
        $this->assertionRepository = $this->createMock(AssertionRepository::class);
        $this->backend = new JwtAssertionGrantBackend(
            $this->assertionKeyRepository,
            $this->jwtConfig->signer(),
            $this->assertionRepository,
            $this->jwtConfig->parser(),
            $this->clock
        );
        $this->accessTokenTtl = new DateInterval('PT1H');
    }

    /**
     * @return AssertionKey&MockObject
     */
    protected function willFindAssertionKey() : AssertionKey
    {
        $key = $this->createMock(AssertionKey::class);
        $key->method('getSigningKey')
            ->willReturn($this->jwtConfig->verificationKey()->contents());
        $key->method('getIdentifier')
            ->willReturn(self::KEY_ID);

        $this->assertionKeyRepository->expects($this->once())
            ->method('getAssertionKeyById')
            ->with(self::KEY_ID)
            ->willReturn($key);

        return $key;
    }

    protected function validAssertion() : UnencryptedToken
    {
        $assertion = $this->jwtConfig->builder()
            ->withHeader(JwtAssertionGrantBackend::HEADER_KEY_ID, self::KEY_ID)
            ->permittedFor(self::AUDIENCE)
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->issuedBy(self::OAUTH_CLIENT_ID)
            ->relatedTo(self::USER_ID)
            ->identifiedBy(self::ASSERTION_ID)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );
        assert($assertion instanceof UnencryptedToken);

        return $assertion;
    }

    public function assertionRequest(string $assertion, ?string $expectedIssuer=null) : AssertionRequest
    {
        assert($assertion !== '');

        return new AssertionRequest(
            $assertion,
            self::AUDIENCE,
            $expectedIssuer,
            $this->accessTokenTtl,
            new ServerRequest()
        );
    }

    private function checkAssertionFailure(string $assertion, string $expectedHint, ?string $expectedIssuer=null) : void
    {
        $error = null;
        try {
            $this->backend->parseAndValidate($this->assertionRequest($assertion, $expectedIssuer));
        } catch (InvalidAssertion $error) {
            // just setting $error
        }

        $this->assertInstanceOf(InvalidAssertion::class, $error);
        $this->assertNotNull($error->getHint());
        $this->assertStringContainsStringIgnoringCase($expectedHint, $error->getHint());
    }
}
