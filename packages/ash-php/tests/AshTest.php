<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Ash;
use Ash\Core\AshMode;
use Ash\Core\BuildProofInput;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the main Ash facade.
 */
final class AshTest extends TestCase
{
    #[Test]
    public function canCanonicalizeJsonThroughFacade(): void
    {
        $result = Ash::canonicalizeJson(['b' => 2, 'a' => 1]);
        $this->assertSame('{"a":1,"b":2}', $result);
    }

    #[Test]
    public function canCanonicalizeUrlEncodedThroughFacade(): void
    {
        $result = Ash::canonicalizeUrlEncoded('b=2&a=1');
        $this->assertSame('a=1&b=2', $result);
    }

    #[Test]
    public function canNormalizeBindingThroughFacade(): void
    {
        $result = Ash::normalizeBinding('post', '/api/update');
        $this->assertSame('POST|/api/update|', $result);
    }

    #[Test]
    public function canBuildProofThroughFacade(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST /api/update',
            contextId: 'test-context-123',
            canonicalPayload: '{"name":"test"}',
        );

        $proof = Ash::buildProof($input);

        $this->assertNotEmpty($proof);
        $this->assertStringNotContainsString('=', $proof);
    }

    #[Test]
    public function canTimingSafeCompareThroughFacade(): void
    {
        $this->assertTrue(Ash::timingSafeCompare('test', 'test'));
        $this->assertFalse(Ash::timingSafeCompare('test', 'other'));
    }

    #[Test]
    public function canBase64UrlEncodeThroughFacade(): void
    {
        $encoded = Ash::base64UrlEncode('hello');
        $decoded = Ash::base64UrlDecode($encoded);

        $this->assertSame('hello', $decoded);
    }

    #[Test]
    public function versionConstantExists(): void
    {
        $this->assertSame('2.3.4', Ash::VERSION);
    }
}
