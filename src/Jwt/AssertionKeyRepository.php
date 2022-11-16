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

/**
 * A storage backend for keys used to verify assertion signatures.
 */
interface AssertionKeyRepository
{
    /**
     * Get a key by its identifier
     *
     * @param string $keyId The assertion key's ID.
     * @return AssertionKey|null null if the key was not found
     */
    public function getAssertionKeyById(string $keyId) : ?AssertionKey;
}
