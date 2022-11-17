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

use PMG\AssertionGrant\Assertion;
use PMG\AssertionGrant\Exception\InvalidAssertionException;
use PMG\AssertionGrant\Jwt\AssertionKey;

class CannotIssueAccessToken extends InvalidAssertionException
{
    public static function to(AssertionKey $key, Assertion $assertion) : self
    {
        return new self('Could not issue access token', sprintf(
            'Assertion key %s declined to issue an access token for the assertion issued by %s for subject %s',
            $key->getIdentifier(),
            $assertion->getIssuer(),
            $assertion->getSubject()
        ));
    }
}
