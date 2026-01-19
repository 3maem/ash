<?php

declare(strict_types=1);

namespace Ash\Tests;

use Ash\Core\AshMode;
use Ash\Core\BuildProofInput;
use Ash\Core\Proof;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Tests for ASH proof generation.
 */
final class ProofTest extends TestCase
{
    #[Test]
    public function proofIsDeterministic(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST /api/update',
            contextId: 'test-context-123',
            canonicalPayload: '{"name":"test"}',
        );

        $proof1 = Proof::build($input);
        $proof2 = Proof::build($input);

        $this->assertSame($proof1, $proof2);
    }

    #[Test]
    public function differentPayloadProducesDifferentProof(): void
    {
        $input1 = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST /api/update',
            contextId: 'test-context-123',
            canonicalPayload: '{"name":"test1"}',
        );
        $input2 = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST /api/update',
            contextId: 'test-context-123',
            canonicalPayload: '{"name":"test2"}',
        );

        $proof1 = Proof::build($input1);
        $proof2 = Proof::build($input2);

        $this->assertNotSame($proof1, $proof2);
    }

    #[Test]
    public function nonceIncludedInProof(): void
    {
        $withoutNonce = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST /api/update',
            contextId: 'test-context-123',
            canonicalPayload: '{"name":"test"}',
        );
        $withNonce = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST /api/update',
            contextId: 'test-context-123',
            canonicalPayload: '{"name":"test"}',
            nonce: 'server-nonce-456',
        );

        $proofWithout = Proof::build($withoutNonce);
        $proofWith = Proof::build($withNonce);

        $this->assertNotSame($proofWithout, $proofWith);
    }

    #[Test]
    public function proofIsValidBase64Url(): void
    {
        $input = new BuildProofInput(
            mode: AshMode::Balanced,
            binding: 'POST /api/update',
            contextId: 'test-context-123',
            canonicalPayload: '{"name":"test"}',
        );

        $proof = Proof::build($input);

        // Should not contain standard Base64 characters replaced by URL-safe ones
        $this->assertStringNotContainsString('+', $proof);
        $this->assertStringNotContainsString('/', $proof);
        $this->assertStringNotContainsString('=', $proof);

        // Should be decodable
        $decoded = Proof::base64UrlDecode($proof);
        $this->assertSame(32, strlen($decoded)); // SHA-256 produces 32 bytes
    }

    #[Test]
    public function base64UrlRoundtrip(): void
    {
        $data = 'hello world';
        $encoded = Proof::base64UrlEncode($data);
        $decoded = Proof::base64UrlDecode($encoded);

        $this->assertSame($data, $decoded);
    }

    #[Test]
    public function base64UrlIsUrlSafe(): void
    {
        // This data produces + and / in standard Base64
        $data = "\xfb\xff\xfe";
        $encoded = Proof::base64UrlEncode($data);

        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
    }

    #[Test]
    public function base64UrlNoPadding(): void
    {
        // "a" would produce padding in standard Base64
        $encoded = Proof::base64UrlEncode('a');
        $this->assertStringNotContainsString('=', $encoded);
    }

    #[Test]
    public function base64UrlDecodeWithPadding(): void
    {
        // Standard Base64 with padding
        $encoded = 'aGVsbG8=';
        $decoded = Proof::base64UrlDecode($encoded);

        $this->assertSame('hello', $decoded);
    }
}
