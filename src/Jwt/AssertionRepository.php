<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Jwt;

use DateTimeImmutable;

/**
 * Storage backend for assertion ID's to prevent replay attacks.
 */
interface AssertionRepository
{
    /**
     * Check to see if the JTI value has been seen before
     *
     * @param string $assertionId the `jti` claim from the web token
     * @return bool True if the assertion ID has been seen before
     */
    public function isAssertionReplay(string $assertionId) : bool;

    /**
     * Persist the assertion ID to the database so it can't be used again
     *
     * @param string $assertionId the jti claim from the web token
     * @param DateTimeImmutable $expiresAt the assertions expiration time
     */
    public function persistNewAssertion(string $assertionId, DateTimeImmutable $expiresAt) : void;
}
