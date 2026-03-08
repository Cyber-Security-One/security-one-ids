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
        // Set a known token for testing. We rely on Config::set to cleanly reset between tests.
        // Unset the env variable just in case the testing environment had it populated.
        putenv('AGENT_TOKEN');
        unset($_ENV['AGENT_TOKEN']);
        unset($_SERVER['AGENT_TOKEN']);
        Config::set('ids.agent_token', 'test-agent-token');
    }

    protected function tearDown(): void
    {
        putenv('AGENT_TOKEN');
        unset($_ENV['AGENT_TOKEN']);
        unset($_SERVER['AGENT_TOKEN']);
        Config::set('ids.agent_token', null);
        parent::tearDown();
    }

    public function test_auth_logic_rejects_missing_token()
    {
        // Missing token
        $this->postJson('/api/rules/update', [])->assertStatus(401);

        // Empty token
        $this->postJson('/api/rules/update?token=', [])->assertStatus(401);

        // Wrong token
        $this->postJson('/api/rules/update?token=wrong-token', [])->assertStatus(401);

        // Valid token should pass
        $this->postJson('/api/rules/update?token=test-agent-token', [])->assertStatus(200);
        $this->postJson('/api/rules/update', [], ['X-Agent-Token' => 'test-agent-token'])->assertStatus(200);
        $this->postJson('/api/rules/update', [], ['Authorization' => 'Bearer test-agent-token'])->assertStatus(200);

        // Empty query token should not override valid bearer/header
        $this->postJson('/api/rules/update?token=', [], ['Authorization' => 'Bearer test-agent-token'])->assertStatus(200);
    }

    public function test_auth_logic_allows_zero_as_token()
    {
        Config::set('ids.agent_token', '0');

        $this->postJson('/api/rules/update?token=0', [])->assertStatus(200);
    }
}
