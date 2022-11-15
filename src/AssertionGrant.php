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
        return $responseType;
    }
}
