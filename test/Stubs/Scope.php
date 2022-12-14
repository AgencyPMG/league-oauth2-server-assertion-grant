<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Test\Stubs;

use League\OAuth2\Server\Entities\ScopeEntityInterface;

final class Scope implements ScopeEntityInterface
{
    /**
     * @param non-empty-string $id
     */
    public function __construct(private string $id)
    {
    }

    /**
     * @return non-empty-string
     */
    public function getIdentifier() : string
    {
        return $this->id;
    }

    public function jsonSerialize() : string
    {
        return $this->id;
    }
}
