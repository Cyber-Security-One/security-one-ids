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
        Config::set('ids.agent_token', 'test-agent-token');
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
        putenv('AGENT_TOKEN=0');
        Config::set('ids.agent_token', '0');

        $this->postJson('/api/rules/update?token=0', [])->assertStatus(200);
    }
}
