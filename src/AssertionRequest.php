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
use Psr\Http\Message\ServerRequestInterface;

/**
 * argument object passed to the Assertion Grant Backend when validating an assertion
 */
final class AssertionRequest
{
    /**
     * @param non-empty-string $assertion the assertions tring from the request body
     * @param non-empty-string $expectedAudience the audience the assertion should be for
     */
    public function __construct(
        private string $assertion,
        private string $expectedAudience,
        private ?string $expectedIssuer,
        private DateInterval $accessTokenTtl,
        private ServerRequestInterface $request
    ) {
    }

    /**
     * @return non-empty-string
     */
    public function getAssertion() : string
    {
        return $this->assertion;
    }

    /**
     * @return non-empty-string
     */
    public function getExpectedAudience() : string
    {
        return $this->expectedAudience;
    }

    public function getExpectedIssuer() : ?string
    {
        return $this->expectedIssuer;
    }

    public function getAccessTokenTtl() : DateInterval
    {
        return $this->accessTokenTtl;
    }

    public function getRequest() : ServerRequestInterface
    {
        return $this->request;
    }
}
