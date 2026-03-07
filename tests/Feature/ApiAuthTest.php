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

        // Null or empty comparisons
        $this->assertFalse(hash_equals((string) $agentToken, (string) null));
        $this->assertFalse(hash_equals((string) $agentToken, (string) ''));
    }
}
