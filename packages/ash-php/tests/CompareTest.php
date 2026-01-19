<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\Compare;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Tests for timing-safe comparison.
 */
final class CompareTest extends TestCase
{
    #[Test]
    public function timingSafeReturnsTrueForEqualStrings(): void
    {
        $this->assertTrue(Compare::timingSafe('test123', 'test123'));
    }

    #[Test]
    public function timingSafeReturnsFalseForDifferentStrings(): void
    {
        $this->assertFalse(Compare::timingSafe('test123', 'test456'));
    }

    #[Test]
    public function timingSafeReturnsFalseForDifferentLengths(): void
    {
        $this->assertFalse(Compare::timingSafe('test', 'testing'));
    }

    #[Test]
    public function timingSafeWorksWithEmptyStrings(): void
    {
        $this->assertTrue(Compare::timingSafe('', ''));
        $this->assertFalse(Compare::timingSafe('', 'test'));
    }

    #[Test]
    public function timingSafeWorksWithSpecialCharacters(): void
    {
        $proof = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_';
        $this->assertTrue(Compare::timingSafe($proof, $proof));
    }
}
