<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Exception;

use League\OAuth2\Server\Exception\OAuthServerException;

/**
 * Base class for exceptions throw from the assertion backend
 */
class AssertionGrantException extends OAuthServerException
{
}
