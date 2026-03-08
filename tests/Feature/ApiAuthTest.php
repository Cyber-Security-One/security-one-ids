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
        $this->getJson('/api/system/version')->assertStatus(401);

        // 2. Invalid token provided via header
        $this->withHeaders(['X-Agent-Token' => 'invalid-token'])
            ->getJson('/api/system/version')
            ->assertStatus(401);

        // 3. Valid token provided via header (using GET for /api/system/version)
        $this->withHeaders(['X-Agent-Token' => 'test-agent-token'])
            ->getJson('/api/system/version')
            ->assertStatus(200);

        // 4. Valid token provided via body (using POST for /api/rules/update)
        $this->postJson('/api/rules/update', [
            'token' => 'test-agent-token',
        ])->assertStatus(200);

        // 5. Valid bearer token provided
        $this->withToken('test-agent-token')
            ->getJson('/api/system/version')
            ->assertStatus(200);

        // 6. Token provided as array (should be rejected)
        $this->postJson('/api/rules/update', [
            'token' => ['test-agent-token'],
        ])->assertStatus(401);
    }
}
