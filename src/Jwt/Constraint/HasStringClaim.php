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

use InvalidArgumentException;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

/**
 * Most of the validation constriants in lcobucci/jwt are aimed at validation
 * specific values of claims (was this issue by X, is the subject Y, etc)
 * but we need to make sure certain clames exist and are strings only.
 */
final class HasStringClaim implements Constraint
{
    /**
     * @var non-empty-string
     */
    private string $claim;

    public function __construct(string $claim)
    {
        assert('' !== $claim, new InvalidArgumentException('$claim cannot be empty'));
        $this->claim = $claim;
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

        if (!$claims->has($this->claim)) {
            throw ConstraintViolation::error(sprintf(
                '%s claim is missing',
                $this->claim
            ), $this);
        }

        if (!is_string($claims->get($this->claim))) {
            throw ConstraintViolation::error(sprintf(
                '%s claim is not a string',
                $this->claim
            ), $this);
        }
    }
}
