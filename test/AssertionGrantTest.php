<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Test;

use DateInterval;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PMG\AssertionGrant\Assertion;
use PMG\AssertionGrant\AssertionGrant;
use PMG\AssertionGrant\AssertionGrantBackend;
use PMG\AssertionGrant\AssertionRequest;
use PMG\AssertionGrant\Test\Stubs\Scope;

class AssertionGrantTest extends TestCase
{
    const AUDIENCE = 'https://example.com/token';
    const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:test-assertion';
    const CLIENT_ID = 'bd6626af-5cb7-4e81-a658-7a6c4d4a7383';
    const NO_CLIENT_ID = null;
    const USER_ID = 'b1b6f14e-3773-44ec-b352-854742f44ffc';
    const ASSERTION = 'this-is-a-test-assertion-pls-ignore';
    const ALLOWED_SCOPE = 'allowed_scope';
    const INVALID_SCOPE = 'invalid_scope';

    /**
     * @var ClientRepositoryInterface&MockObject
     */
    private ClientRepositoryInterface $clientRepository;

    /**
     * @var ScopeRepositoryInterface&MockObject
     */
    private ScopeRepositoryInterface $scopeRepository;

    /**
     * @var AccessTokenRepositoryInterface&MockObject
     */
    private AccessTokenRepositoryInterface $tokenRepository;

    /**
     * @var AssertionGrantBackend&MockObject
     */
    private AssertionGrantBackend $assertionBackend;

    private AssertionGrant $grant;

    /**
     * @var ResponseTypeInterface&MockObject
     */
    private ResponseTypeInterface $responseType;

    private DateInterval $accessTokenTtl;

    /**
     * @var Assertion&Stub
     */
    private Assertion $assertion;

    /**
     * @var ClientEntityInterface&Stub
     */
    private ClientEntityInterface $oauthClient;

    public function testGetIdentifierUsesGrantTypeFromAssertionBackend() : void
    {
        $this->assertionBackend->expects($this->once())
            ->method('getGrantType')
            ->willReturn(self::GRANT_TYPE);

        $result = $this->grant->getIdentifier();

        $this->assertSame(self::GRANT_TYPE, $result);
    }

    public function testRequestsWithoutAssertionError() : void
    {
        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage('missing a required parameter');

        $this->grant->respondToAccessTokenRequest(
            $this->request([]),
            $this->responseType,
            $this->accessTokenTtl
        );
    }

    /**
     * Not testing any "unhappy" paths through client validation, theoretically
     * that's handled in the tests in the core library
     */
    public function testClientIdInRequestsValidatesClient() : void
    {
        $request = $this->request([
            'client_id' => self::CLIENT_ID,
            'client_secret' => __METHOD__,
            'assertion' => self::ASSERTION,
        ]);
        $this->willParseAndValidateAssertion($request, self::CLIENT_ID);
        $this->willGetClientEntity();
        $this->clientRepository->expects($this->once())
            ->method('validateClient')
            ->with(self::CLIENT_ID, __METHOD__, self::GRANT_TYPE)
            ->willReturn(true);
        $this->assertion->method('getAllowedScopes')
            ->willReturn([]);
        $token = $this->willIssueAccessToken();

        $result = $this->grant->respondToAccessTokenRequest(
            $request,
            $this->responseType,
            $this->accessTokenTtl
        );

        $this->assertSame($this->responseType, $result);
    }

    public function testClientCredentialsInRequestWithInvalidSecretStillErrors() : void
    {
        $request = $this->request([
            'client_id' => self::CLIENT_ID,
            'client_secret' => __METHOD__,
            'assertion' => self::ASSERTION,
        ]);
        $this->clientRepository->expects($this->once())
            ->method('validateClient')
            ->with(self::CLIENT_ID, __METHOD__, self::GRANT_TYPE)
            ->willReturn(false);

        $error = null;
        try {
            $this->grant->respondToAccessTokenRequest(
                $request,
                $this->responseType,
                $this->accessTokenTtl
            );
        } catch (OAuthServerException $error) {
            // setting $error
        }

        $this->assertInstanceOf(OAuthServerException::class, $error);
        $this->assertStringContainsStringIgnoringCase('client authentication failed', $error->getMessage());
    }

    public function testClientIdNotInRequestUsesIssuerToLookUpClient() : void
    {
        $this->assertion->method('getIssuer')
            ->willReturn(self::CLIENT_ID);
        $request = $this->request([
            'assertion' => self::ASSERTION,
        ]);
        $this->willParseAndValidateAssertion($request, self::NO_CLIENT_ID);
        $this->willGetClientEntity();
        $this->clientRepository->expects($this->never())
            ->method('validateClient');
        $this->assertion->method('getAllowedScopes')
            ->willReturn([]);
        $token = $this->willIssueAccessToken();

        $result = $this->grant->respondToAccessTokenRequest(
            $request,
            $this->responseType,
            $this->accessTokenTtl
        );

        $this->assertsame($this->responseType, $result);
    }

    public function testScopesRequestButNotInAssertionCauseErrors() : void
    {
        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage('requested scope is invalid');

        $this->assertion->method('getIssuer')
            ->willReturn(self::CLIENT_ID);
        $request = $this->request([
            'assertion' => self::ASSERTION,
            'scope' => self::INVALID_SCOPE,
        ]);
        $this->willParseAndValidateAssertion($request, self::NO_CLIENT_ID);
        $this->willGetClientEntity();

        $this->assertion->method('getAllowedScopes')
            ->willReturn([self::ALLOWED_SCOPE]);
        $this->scopeRepository->expects($this->once())
            ->method('getScopeEntityByIdentifier')
            ->with(self::INVALID_SCOPE)
            ->willReturn(new Scope(self::INVALID_SCOPE));

        $this->grant->respondToAccessTokenRequest(
            $request,
            $this->responseType,
            $this->accessTokenTtl
        );
    }

    public function testValidScopesInRequestIssueAccessToken() : void
    {
        $this->assertion->method('getIssuer')
            ->willReturn(self::CLIENT_ID);
        $request = $this->request([
            'assertion' => self::ASSERTION,
            'scope' => self::ALLOWED_SCOPE,
        ]);
        $this->willParseAndValidateAssertion($request, self::NO_CLIENT_ID);
        $this->willGetClientEntity();
        $scope = new Scope(self::ALLOWED_SCOPE);
        $this->assertion->method('getAllowedScopes')
            ->willReturn([self::ALLOWED_SCOPE]);
        $this->scopeRepository->expects($this->once())
            ->method('getScopeEntityByIdentifier')
            ->with(self::ALLOWED_SCOPE)
            ->willReturn($scope);
        $this->willIssueAccessToken([$scope]);

        $result = $this->grant->respondToAccessTokenRequest(
            $request,
            $this->responseType,
            $this->accessTokenTtl
        );

        $this->assertSame($this->responseType, $result);
    }

    public function testNoScopesInRequestDefaultsToScopesFromAssertion() : void
    {
        $this->assertion->method('getIssuer')
            ->willReturn(self::CLIENT_ID);
        $request = $this->request([
            'assertion' => self::ASSERTION,
        ]);
        $this->willParseAndValidateAssertion($request, self::NO_CLIENT_ID);
        $this->willGetClientEntity();
        $scope = new Scope(self::ALLOWED_SCOPE);
        $this->assertion->method('getAllowedScopes')
            ->willReturn([self::ALLOWED_SCOPE]);
        $this->scopeRepository->expects($this->once())
            ->method('getScopeEntityByIdentifier')
            ->with(self::ALLOWED_SCOPE)
            ->willReturn($scope);
        $this->willIssueAccessToken([$scope]);

        $result = $this->grant->respondToAccessTokenRequest(
            $request,
            $this->responseType,
            $this->accessTokenTtl
        );

        $this->assertSame($this->responseType, $result);
    }

    protected function setUp() : void
    {
        $this->clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $this->scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $this->tokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $this->assertionBackend = $this->createMock(AssertionGrantBackend::class);
        $this->grant = new AssertionGrant(
            $this->assertionBackend,
            self::AUDIENCE,
        );
        $this->grant->setClientRepository($this->clientRepository);
        $this->grant->setScopeRepository($this->scopeRepository);
        $this->grant->setAccessTokenRepository($this->tokenRepository);
        $keyPath = __DIR__.'/Resources/test_key.pem';
        chmod($keyPath, 0600);
        $this->grant->setPrivateKey(new CryptKey($keyPath));
        $this->responseType = $this->createMock(ResponseTypeInterface::class);
        $this->accessTokenTtl = new DateInterval('PT1H');
        $this->assertion = $this->createStub(Assertion::class);
        $this->oauthClient = $this->createStub(ClientEntityInterface::class);

        $this->assertion->method('getSubject')
            ->willReturn(self::USER_ID);
        $this->assertionBackend->expects($this->any())
            ->method('getGrantType')
            ->willReturn(self::GRANT_TYPE);
    }

    /**
     * @param array<string, mixed> $bodyParams
     */
    protected function request(array $bodyParams) : ServerRequest
    {
        $bodyParams['grant_type'] = 'urn:ietf:params:oauth:grant-type:example';

        return new ServerRequest(
            [], // server params
            [], // uploaded files
            '/token',
            'POST',
            (new StreamFactory())->createStream(http_build_query($bodyParams)),
            [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            [], // cookies
            [], // query params
            $bodyParams
        );
    }

    private function willParseAndValidateAssertion(ServerRequest $request, ?string $clientId) : void
    {
        $this->assertionBackend->expects($this->once())
            ->method('parseAndValidate')
            ->with(new AssertionRequest(
                self::ASSERTION,
                self::AUDIENCE,
                $clientId,
                $this->accessTokenTtl,
                $request
            ))
            ->willReturn($this->assertion);
    }

    private function willGetClientEntity() : void
    {
        $this->clientRepository->expects($this->once())
            ->method('getClientEntity')
            ->with(self::CLIENT_ID)
            ->willReturn($this->oauthClient);
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return AccessTokenEntityInterface&Stub
     */
    private function willIssueAccessToken(array $scopes=[]) : AccessTokenEntityInterface
    {
        $token = $this->createStub(AccessTokenEntityInterface::class);

        $this->tokenRepository->expects($this->once())
            ->method('getNewToken')
            ->with($this->identicalTo($this->oauthClient), $scopes, self::USER_ID)
            ->willReturn($token);
        $this->tokenRepository->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($this->identicalTo($token));

        // everything goes through finalizeScopes, so we can put that here
        $this->scopeRepository->expects($this->once())
            ->method('finalizeScopes')
            ->with($scopes, self::GRANT_TYPE, $this->identicalTo($this->oauthClient), self::USER_ID)
            ->willReturn($scopes);

        $this->responseType->expects($this->once())
            ->method('setAccessToken')
            ->with($this->identicalTo($token));

        return $token;
    }
}
