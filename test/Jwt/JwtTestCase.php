<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Test\Jwt;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha384;
use Lcobucci\JWT\Signer\Key\InMemory;
use PMG\AssertionGrant\Test\TestCase;

abstract class JwtTestCase extends TestCase
{
    protected static function createJwtConfiguration() : Configuration
    {
        return Configuration::forAsymmetricSigner(
            new Sha384(),
            InMemory::file(__DIR__.'/../Resources/test_key.pem'),
            InMemory::file(__DIR__.'/../Resources/test_key_public.pem')
        );
    }
}
