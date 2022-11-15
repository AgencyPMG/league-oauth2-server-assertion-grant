<?php declare(strict_types=1);
/**
 * This file is part of pmg/league-oauth2-server-jwt-bearer.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Exception;

use Throwable;

/**
 * Thrown when an assertion cannot be verified. This has the error type
 * defined in RFC7521.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7521#section-4.1.1
 */
class InvalidAssertionException extends AssertionGrantException
{
    public const ERROR_TYPE = 'invalid_grant';

    public function __construct(string $message, ?string $hint=null, int $code=0, ?Throwable $previous=null)
    {
        parent::__construct(
            $message,
            $code,
            self::ERROR_TYPE,
            400, // 400 Bad Request
            $hint,
            null, // redirect uri
            $previous
        );
    }
}
