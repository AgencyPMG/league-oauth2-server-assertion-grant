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

class AssertionKeyNotFound extends InvalidAssertionException
{
    public static function with(string $keyId) : self
    {
        return self::create(sprintf(
            'Assertion key %s not found, could not verify JSON web token signaturesignature',
            $keyId
        ), 'Check the `kid` header');
    }
}
