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

use DateTimeImmutable;
use PMG\AssertionGrant\DefaultAssertion;

class DefaultAssertionTest extends TestCase
{
    const SUBJECT = 'd21386bb-2360-4bae-ba13-e57f4768b365';
    const ISSUER = 'f1e78d2a-039f-492b-b2dc-298f8f653e8a';
    const AUDIENCE = 'https://example.com/token';
    const SCOPES = ['test-scope'];

    public function testValuesFromConstructorAreReturnedFromGetters() : void
    {
        $expires = new DateTimeImmutable();
        $issued = new DateTimeImmutable();

        $assertion = new DefaultAssertion(
            self::ISSUER,
            self::SUBJECT,
            self::AUDIENCE,
            $expires,
            $issued,
            self::SCOPES,
        );

        $this->assertSame(self::ISSUER, $assertion->getIssuer());
        $this->assertSame(self::SUBJECT, $assertion->getSubject());
        $this->assertSame($expires, $assertion->getExpiresAt());
        $this->assertSame($issued, $assertion->getIssuedAt());
        $this->assertSame(self::SCOPES, $assertion->getAllowedScopes());
    }

    public function testNullIssueTimeIsAllowed() : void
    {
        $expires = new DateTimeImmutable();

        $assertion = new DefaultAssertion(
            self::ISSUER,
            self::SUBJECT,
            self::AUDIENCE,
            $expires,
            null,
            self::SCOPES,
        );

        $this->assertNull($assertion->getIssuedAt());
    }
}
