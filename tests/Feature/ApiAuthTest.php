<?php

namespace Tests\Feature;

use Tests\TestCase;

class ApiAuthTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['ids.agent_token' => 'test-agent-token']);
    }

    public function test_api_routes_require_valid_agent_token()
    {
        // 1. No token provided
        $this->postJson('/api/rules/update')->assertStatus(401);

        // 2. Invalid token provided via header
        $this->withHeaders(['X-Agent-Token' => 'invalid-token'])
            ->postJson('/api/rules/update')
            ->assertStatus(401);

        // 3. Valid token provided via header
        $this->withHeaders(['X-Agent-Token' => 'test-agent-token'])
            ->postJson('/api/rules/update', [
                'global_rules' => [],
                'agent_rules' => [],
            ])
            ->assertStatus(200);

        // 4. Valid token provided via body
        $this->postJson('/api/rules/update', [
            'token' => 'test-agent-token',
            'global_rules' => [],
            'agent_rules' => [],
        ])->assertStatus(200);

        // 5. Valid bearer token provided
        $this->withToken('test-agent-token')
            ->postJson('/api/rules/update', [
                'global_rules' => [],
                'agent_rules' => [],
            ])->assertStatus(200);
    }
}
