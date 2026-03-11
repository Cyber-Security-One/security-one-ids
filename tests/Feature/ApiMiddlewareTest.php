<?php

namespace Tests\Feature;

use Tests\TestCase;

class ApiMiddlewareTest extends TestCase
{
    private string|false $originalAgentToken;

    protected function setUp(): void
    {
        parent::setUp();

        $this->originalAgentToken = getenv('AGENT_TOKEN');
        putenv('AGENT_TOKEN');
    }

    protected function tearDown(): void
    {
        if ($this->originalAgentToken === false) {
            putenv('AGENT_TOKEN');
        } else {
            putenv('AGENT_TOKEN=' . $this->originalAgentToken);
        }

        parent::tearDown();
    }

    /**
     * Test when AGENT_TOKEN is empty.
     */
    public function test_api_middleware_fails_if_agent_token_not_configured()
    {
        $this->app['config']->set('ids.agent_token', '');

        $response = $this->get('/api/system/version', [
            'X-Agent-Token' => 'some-token',
        ]);

        $response->assertStatus(401);
        $response->assertJson(['error' => 'Unauthorized']);
    }

    /**
     * Test when provided token is invalid.
     */
    public function test_api_middleware_unauthorized_if_token_invalid()
    {
        $this->app['config']->set('ids.agent_token', 'valid-secret-token');

        $response = $this->get('/api/system/version', [
            'X-Agent-Token' => 'invalid-token',
        ]);

        $response->assertStatus(401);
        $response->assertJson(['error' => 'Unauthorized']);
    }

    /**
     * Test when provided token is valid.
     */
    public function test_api_middleware_succeeds_with_valid_token()
    {
        $this->app['config']->set('ids.agent_token', 'valid-secret-token');

        $response = $this->get('/api/system/version', [
            'X-Agent-Token' => 'valid-secret-token',
        ]);

        $response->assertStatus(200);
    }

    /**
     * Test bypassing with empty token when agent token is set.
     */
    public function test_api_middleware_unauthorized_if_token_empty()
    {
        $this->app['config']->set('ids.agent_token', 'valid-secret-token');

        $response = $this->get('/api/system/version', [
            'X-Agent-Token' => '',
        ]);

        $response->assertStatus(401);
        $response->assertJson(['error' => 'Unauthorized']);
    }
}
