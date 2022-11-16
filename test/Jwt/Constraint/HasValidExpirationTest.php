<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Test\Jwt\Constraint;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PMG\AssertionGrant\Jwt\Constraint\HasValidExpiration;
use PMG\AssertionGrant\Test\Jwt\JwtTestCase;

class HasValidExpirationTest extends JwtTestCase
{
    private Configuration $jwtConfig;
    private DateTimeImmutable $now;
    private FrozenClock $clock;
    private DateInterval $maxTtl;

    public function testNonPlainTokensCauseErrors() : void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('only plaintext tokens are supported');

        $token = $this->createMock(Token::class);

        $this->jwtConfig->validator()->assert($token, new HasValidExpiration(
            $this->clock,
            $this->maxTtl
        ));
    }

    public function testCurrentTimeIsUsedToValidatedExpirationIfNbfAndIssuedAtIsMissing() : void
    {
        $token = $this->jwtConfig->builder()
            ->expiresAt($this->now->add(new DateInterval('PT30M')))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $ok = $this->jwtConfig->validator()->validate($token, new HasValidExpiration(
            $this->clock,
            $this->maxTtl
        ));

        $this->assertTrue($ok);
    }

    public function testNotBeforeClaimIsUsedToCheckExpirationTimeIfPresent() : void
    {
        // 30 minute window between nbf and expiration
        $token = $this->jwtConfig->builder()
            ->canOnlyBeUsedAfter($this->now->add(new DateInterval('PT1H30M')))
            ->expiresAt($this->now->add(new DateInterval('PT2H')))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $ok = $this->jwtConfig->validator()->validate($token, new HasValidExpiration(
            $this->clock,
            $this->maxTtl
        ));

        $this->assertTrue($ok);
    }

    public function testIssuededAtIsUsedToCheckExpirationTimeIfPresent() : void
    {
        // 30 minute window between nbf and expiration
        $token = $this->jwtConfig->builder()
            ->issuedAt($this->now->sub(new DateInterval('PT30M')))
            ->expiresAt($this->now->add(new DateInterval('PT20M')))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $ok = $this->jwtConfig->validator()->validate($token, new HasValidExpiration(
            $this->clock,
            $this->maxTtl
        ));

        $this->assertTrue($ok);
    }

    public function testTokensWithTtlTooWideFromCurrentTimeCauseErrors() : void
    {
        $this->expectException(RequiredConstraintsViolated::class);

        $token = $this->jwtConfig->builder()
            ->expiresAt($this->now->add(new DateInterval('PT2H')))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $this->jwtConfig->validator()->assert($token, new HasValidExpiration(
            $this->clock,
            $this->maxTtl
        ));
    }

    public function testTokensWithTtlTooWideFromCurrentNotBeforeCauseErrors() : void
    {
        $this->expectException(RequiredConstraintsViolated::class);

        $token = $this->jwtConfig->builder()
            ->canOnlyBeUsedAfter($this->now->add(new DateInterval('PT1H30M')))
            ->expiresAt($this->now->add(new DateInterval('PT3H')))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $this->jwtConfig->validator()->assert($token, new HasValidExpiration(
            $this->clock,
            $this->maxTtl
        ));
    }

    public function testTokensWithTtlTooWideFromCurrentIssuedAtCauseErrors() : void
    {
        $this->expectException(RequiredConstraintsViolated::class);

        $token = $this->jwtConfig->builder()
            ->issuedAt($this->now->sub(new DateInterval('PT30M')))
            ->expiresAt($this->now->add(new DateInterval('PT1H30M')))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $this->jwtConfig->validator()->assert($token, new HasValidExpiration(
            $this->clock,
            $this->maxTtl
        ));
    }

    protected function setUp() : void
    {
        $this->jwtConfig = self::createJwtConfiguration();
        $this->now = new DateTimeImmutable('2022-11-14 00:00:00');
        $this->clock = new FrozenClock($this->now);
        $this->maxTtl = new DateInterval('PT1H');
    }
}
