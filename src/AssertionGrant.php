<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant;

use DateInterval;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A grant that implements the assertion authorization grant flow described
 * in RFC7521.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7521
 */
class AssertionGrant extends AbstractGrant
{
    const PARAM_ASSERTION = 'assertion';

    /**
     * @param non-empty-string $expectedAudience the audience for the assertions, this is likely your servers token URL
     */
    public function __construct(
        private AssertionGrantBackend $assertionBackend,
        private string $expectedAudience,
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier() : string
    {
        return $this->assertionBackend->getGrantType();
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTtl
    ) : ResponseTypeInterface {
        $clientId = null;
        try {
            [$clientId] = $this->getClientCredentials($request);
        } catch (OAuthServerException $e) {
            // make client_id optional. if it's present we'll process and
            // validated it, otherwise we'll just use the assertion
            if ($e->getHint() === null || !str_contains($e->getHint(), 'client_id')) {
                throw $e;
            }
        }

        $assertionString = $this->getAssertion($request);

        $assertion = $this->assertionBackend->parseAndValidate(new AssertionRequest(
            $this->getAssertion($request),
            $this->expectedAudience,
            $clientId,
            $accessTokenTtl,
            $request
        ));

        // if we have a client Id in the request do normal client authentication
        // processing here. Otherwise we just pull the client from the `iss`
        // claim in the assertion.
        if ($clientId !== null) {
            $oauthClient = $this->validateClient($request);
        } else {
            $oauthClient = $this->getClientEntityOrFail($assertion->getIssuer(), $request);
        }

        $scopes = $this->getScopes($request, $oauthClient, $assertion);

        $accessToken = $this->issueAccessToken(
            $accessTokenTtl,
            $oauthClient,
            $assertion->getSubject(),
            $scopes,
        );

        $this->getEmitter()->emit(new RequestAccessTokenEvent(
            RequestEvent::ACCESS_TOKEN_ISSUED,
            $request,
            $accessToken
        ));

        $responseType->setAccessToken($accessToken);

        return $responseType;
    }

    /**
     * Pull the `assertion` parameter out of the request and parse it as the
     * JWT its meant to be.
     *
     * @return non-empty-string
     */
    private function getAssertion(ServerRequestInterface $request) : string
    {
        $assertion = $this->getRequestParameter(self::PARAM_ASSERTION, $request, null);
        if (!\is_string($assertion) || $assertion === '') {
            throw OAuthServerException::invalidRequest(self::PARAM_ASSERTION);
        }

        return $assertion;
    }

    /**
     * @return ScopeEntityInterface[]
     */
    private function getScopes(
        ServerRequestInterface $request,
        ClientEntityInterface $oauthClient,
        Assertion $assertion
    ) : array {
        $allowedScopes = $assertion->getAllowedScopes();

        $requestScopes = $this->getRequestParameter(
            'scope',
            $request,
            $allowedScopes, // default to the scopes associated with assertion already
        );

        $scopes = $this->validateScopes($requestScopes ?? []);

        // RFC say we have to limit the scopes to what was originally issued
        // out of band to make the assertion valid.
        foreach ($scopes as $scope) {
            if (!in_array($scope->getIdentifier(), $allowedScopes, true)) {
                throw OAuthServerException::invalidScope($scope->getIdentifier());
            }
        }

        return $this->scopeRepository->finalizeScopes(
            $scopes,
            $this->getIdentifier(),
            $oauthClient,
            $assertion->getSubject(),
        );
    }
}
