<?php declare(strict_types=1);
/**
 * This file is part of pmg/league-oauth2-server-jwt-bearer.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant;

use DateTimeImmutable;

/**
 * This is the actual assertion object parsed from a string. The methods
 * here reflect what the assertion framework in RFC7521 describes
 *
 * @see https://www.rfc-editor.org/rfc/rfc7521#section-5
 */
interface Assertion
{
    /**
     * Get the issuer of the assertion. This will be an oauth client ID
     *
     * @return non-empty-string
     */
    public function getIssuer() : string;

    /**
     * get the subject of the assertion. This will be the user or oauth client id
     *
     * @return non-empty-string
     */
    public function getSubject() : string;

    /**
     * Get the audience of the assertion. This is likely the IDP's domain or
     * token URL.
     *
     * @return non-empty-string
     */
    public function getAudience() : string;

    /**
     * Get the assertion's expiration time.
     */
    public function getExpiresAt() : DateTimeImmutable;

    /**
     * Get the assertion's issue time.
     */
    public function getIssuedAt() : ?DateTimeImmutable;

    /**
     * Get the set of scopes the assertion is allowed to use.
     *
     * @return non-empty-string[] an array of scope identifiers that the the token will be granted
     */
    public function getAllowedScopes() : array;
}
