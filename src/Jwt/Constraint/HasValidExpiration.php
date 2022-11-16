<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Jwt\Constraint;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\Clock;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * This ensures two things:
 *
 * 1. The token expiration is set (it _must_ be set)
 * 2. The valid window (between the nbf claim or now and expiration) is not longer
 *    than the given max ttl
 *
 * Max TTL here will be the access token TTL. An assertion should never be
 * valid for > than the access token TTL.
 */
final class HasValidExpiration implements Constraint
{
    private Clock $clock;

    private DateInterval $maxTtl;

    public function __construct(Clock $clock, DateInterval $maxTtl)
    {
        $this->clock = $clock;
        $this->maxTtl = $maxTtl;
    }

    public function assert(Token $token) : void
    {
        if (!$token instanceof UnencryptedToken) {
            throw ConstraintViolation::error(
                'only plaintext tokens are supported',
                $this
            );
        }

        $claims = $token->claims();

        $notBefore = $claims->get(
            RegisteredClaims::NOT_BEFORE,
            $claims->get(RegisteredClaims::ISSUED_AT, $this->clock->now())
        );
        assert($notBefore instanceof DateTimeImmutable);

        // date intervals are not compareable, so add the maxTtl to the `$notBefore`
        // value and if the token is not expired by that point, it's invalid
        // of note here is that JWTs without assertions will also never be
        // expired and will fail this check.
        if (!$token->isExpired($notBefore->add($this->maxTtl))) {
            throw ConstraintViolation::error(
                'expiration time is missing or too far in the future',
                $this
            );
        }
    }
}
