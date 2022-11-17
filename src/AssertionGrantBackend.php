<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant;

use PMG\AssertionGrant\Exception\InvalidAssertionException;

/**
 * assertion grant backends do the heavy lifting of actually verifying and validating
 * assertions so they can actually be used.
 */
interface AssertionGrantBackend
{
    /**
     * Get the grant type (eg `urn:ietf:params:oauth:grant-type:{GRANT_TYPE}`
     */
    public function getGrantType() : string;

    /**
     * Parse and validate an assertion into an assertion object.
     *
     * The _big_ assumption here is that whatever the backend is will have better
     * facilities to check things like expected audience, expiration, etc vs
     * whatever the actual grant type can do. So we outsource all of that to
     * the backend.
     *
     * @throws InvalidAssertionException if anything is wrong with the assertion
     */
    public function parseAndValidate(AssertionRequest $request) : Assertion;
}
