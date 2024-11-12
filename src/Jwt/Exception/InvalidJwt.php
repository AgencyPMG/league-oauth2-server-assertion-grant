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

use Throwable;
use PMG\AssertionGrant\Exception\InvalidAssertionException;

class InvalidJwt extends InvalidAssertionException
{
    public static function wrap(Throwable $cause) : self
    {
        return self::create(
            $cause->getMessage(),
            null,
            $cause->getCode(),
            $cause
        );
    }
}
