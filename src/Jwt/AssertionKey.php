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

use PMG\AssertionGrant\Assertion;

/**
 * This is the assertion signing key entity interface.
 */
interface AssertionKey
{
    /**
     * Get the key identifier (this would be sent in a `kid` header of a JWT).
     *
     * @return string a key identifier
     */
    public function getIdentifier() : string;

    /**
     * Get the key that will be used to verify the signature of a JWT
     *
     * @return non-empty-string the verificaiton key to use to check the JWT signature
     */
    public function getSigningKey() : string;

    /**
     * Get the scopes that assertions signed with key are allowed to use.
     *
     * @return non-empty-string[]
     */
    public function getAllowedScopes() : array;

    /**
     * Can the assertion key be used to issue a token for the given assertion?
     *
     * This is used as the final validation step.
     *
     * @param Assertion $assertion the assertion that's already been validated
     * @return bool True if a token can be issued
     */
    public function canIssueAccessTokenTo(Assertion $assertion) : bool;
}
