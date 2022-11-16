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

use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PMG\AssertionGrant\Exception\InvalidAssertionException;

class InvalidAssertion extends InvalidAssertionException
{
    public static function wrap(RequiredConstraintsViolated $violations) : self
    {
        $hint = [];
        foreach ($violations->violations() as $violation) {
            $hint[] = $violation->getMessage();
        }

        return new self(
            'Could not validate assertion',
            sprintf('Errors: %s', implode(', ', $hint)),
            $violations->getCode(),
            $violations,
        );
    }

    public static function replay(string $assertionId) : self
    {
        return new self(sprintf('assertion %s has already been used', $assertionId));
    }
}
