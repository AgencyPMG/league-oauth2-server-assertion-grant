<?php declare(strict_types=1);
/**
 * This file is part of pmg/assertion-grant.
 *
 * Copyright (c) PMG <https://www.pmg.com>
 *
 * For full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 */

namespace PMG\AssertionGrant\Test\Jwt\Constraint;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PMG\AssertionGrant\Jwt\Constraint\HasStringClaim;
use PMG\AssertionGrant\Test\Jwt\JwtTestCase;

class HasStringClaimTest extends JwtTestCase
{
    private Configuration $jwtConfig;

    public function testNonPlainTokensCauseErrors() : void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('only plaintext tokens are supported');

        $token = $this->createMock(Token::class);

        $this->jwtConfig->validator()->assert($token, new HasStringClaim('example'));
    }

    public function testTokensWithoutTheExpectedClaimCauseErrors() : void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('example claim is missing');

        $token = $this->jwtConfig->builder()
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $this->jwtConfig->validator()->assert($token, new HasStringClaim('example'));
    }

    public function testTokensWithNonStringClaimCauseErrors() : void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('example claim is not a string');

        $token = $this->jwtConfig->builder()
            ->withClaim('example', false)
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $this->jwtConfig->validator()->assert($token, new HasStringClaim('example'));
    }

    public function testTokensWithStringClaimAreOk() : void
    {
        $token = $this->jwtConfig->builder()
            ->withClaim('example', __METHOD__)
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $ok = $this->jwtConfig->validator()->validate($token, new HasStringClaim('example'));

        $this->assertTrue($ok);
    }

    protected function setUp() : void
    {
        $this->jwtConfig = self::createJwtConfiguration();
    }
}
