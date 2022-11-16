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
use PMG\AssertionGrant\AssertionRequest;

class AssertionRequestTest extends TestCase
{
    const AUDIENCE = 'd21386bb-2360-4bae-ba13-e57f4768b365';
    const CLIENT_ID = 'f1e78d2a-039f-492b-b2dc-298f8f653e8a';
    const ASSERTION = 'test-assertion-pls-ignore';

    public function testValuesFromConstructorAreReturnedFromGetters() : void
    {
        $serverRequest = new ServerRequest();
        $ttl = new DateInterval('PT1H');

        $request = new AssertionRequest(
            self::ASSERTION,
            self::AUDIENCE,
            self::CLIENT_ID,
            $ttl,
            $serverRequest
        );

        $this->assertSame(self::ASSERTION, $request->getAssertion());
        $this->assertSame(self::AUDIENCE, $request->getExpectedAudience());
        $this->assertSame(self::CLIENT_ID, $request->getExpectedIssuer());
        $this->assertSame($ttl, $request->getAccessTokenTtl());
        $this->assertSame($serverRequest, $request->getServerRequest());
    }

    public function testNullExpectedIssuersAreAllowed() : void
    {
        $serverRequest = new ServerRequest();
        $ttl = new DateInterval('PT1H');

        $request = new AssertionRequest(
            self::ASSERTION,
            self::AUDIENCE,
            null,
            $ttl,
            $serverRequest
        );

        $this->assertNull($request->getExpectedIssuer());
    }
}
