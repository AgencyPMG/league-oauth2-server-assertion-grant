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

use DateTimeImmutable;
use InvalidArgumentException;

/**
 * Simple implementation of `Assertion` which no backend specific logic
 */
class DefaultAssertion implements Assertion
{
    /**
     * @param non-empty-string $issuer
     * @param non-empty-string $subject
     * @param non-empty-string $audience
     * @param non-empty-string[] $allowedScopes
     */
    public function __construct(
        private string $issuer,
        private string $subject,
        private string $audience,
        private DateTimeImmutable $expiresAt,
        private ?DateTimeImmutable $issuedAt,
        private array $allowedScopes,
    ) {
        assert($this->issuer !== '', new InvalidArgumentException('$issuer cannot be empty'));
        assert($this->subject !== '', new InvalidArgumentException('$subject cannot be empty'));
        assert($this->audience !== '', new InvalidArgumentException('$audience cannot be empty'));
    }

    /**
     * @return non-empty-string
     */
    public function getIssuer() : string
    {
        return $this->issuer;
    }

    /**
     * @return non-empty-string
     */
    public function getSubject() : string
    {
        return $this->subject;
    }

    /**
     * @return non-empty-string
     */
    public function getAudience() : string
    {
        return $this->audience;
    }

    public function getExpiresAt() : DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function getIssuedAt() : ?DateTimeImmutable
    {
        return $this->issuedAt;
    }

    public function getAllowedScopes() : array
    {
        return $this->allowedScopes;
    }
}
