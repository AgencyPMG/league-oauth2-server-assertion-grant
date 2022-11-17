<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Jwt\Exception;

use PMG\AssertionGrant\Exception\InvalidAssertionException;

class InvalidKeyId extends InvalidAssertionException
{
    public static function missing() : self
    {
        return new self('The assertion does not have a `kid` header');
    }

    public static function invalidType(mixed $keyId) : self
    {
        return new self(sprintf(
            'The `kid` header must be a string, got `%s`',
            get_debug_type($keyId)
        ));
    }
}
