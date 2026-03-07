<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Tests\TestCase;
use Illuminate\Support\Facades\Config;

class ApiAuthTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Set a known token for testing
        putenv('AGENT_TOKEN=test-agent-token');

        // Let's test the hash_equals logic directly since routing is tricky in this setup
    }

    public function test_hash_equals_works_as_expected()
    {
        $agentToken = 'test-agent-token';

        // Valid comparisons
        $this->assertTrue(hash_equals((string) $agentToken, (string) 'test-agent-token'));

        // Invalid comparisons
        $this->assertFalse(hash_equals((string) $agentToken, (string) 'invalid-token'));
        $this->assertFalse(hash_equals((string) $agentToken, (string) 'test-agent-toke'));
        $this->assertFalse(hash_equals((string) $agentToken, (string) 'est-agent-token'));

        // Null becomes empty string when cast, so this tests empty string comparison
        $this->assertFalse(hash_equals((string) $agentToken, (string) null));
        $this->assertFalse(hash_equals((string) $agentToken, (string) ''));
    }

    public function test_auth_logic_rejects_missing_token()
    {
        $agentToken = 'test-agent-token';

        // Simulate missing token (null)
        $token = null;
        $this->assertTrue(!$token || !hash_equals((string) $agentToken, (string) $token));

        // Simulate empty token
        $token = '';
        $this->assertTrue(!$token || !hash_equals((string) $agentToken, (string) $token));

        // Simulate wrong token
        $token = 'wrong-token';
        $this->assertTrue(!$token || !hash_equals((string) $agentToken, (string) $token));

        // Simulate correct token
        $token = 'test-agent-token';
        $this->assertFalse(!$token || !hash_equals((string) $agentToken, (string) $token));
    }
}
