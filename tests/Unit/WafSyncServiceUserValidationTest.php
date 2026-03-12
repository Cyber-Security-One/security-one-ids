<?php

namespace Tests\Unit;

use Tests\TestCase;

class WafSyncServiceUserValidationTest extends TestCase
{
    private \App\Services\WafSyncService $service;

    protected function setUp(): void
    {
        parent::setUp();
        // Instantiate the actual service to test its method directly
        $this->service = new \App\Services\WafSyncService();
    }

    /**
     * Test valid macOS usernames according to the regex pattern
     */
    public function testValidMacOsUsernames()
    {
        $this->assertTrue($this->service->isValidMacOsUsername('john.doe'));
        $this->assertTrue($this->service->isValidMacOsUsername('user_123'));
        $this->assertTrue($this->service->isValidMacOsUsername('admin-user'));
        $this->assertTrue($this->service->isValidMacOsUsername('johndoe'));
    }

    /**
     * Test invalid macOS usernames according to the regex pattern
     * These should be rejected to prevent shell injection while preserving path parsing
     */
    public function testInvalidMacOsUsernames()
    {
        // Reject spaces
        $this->assertFalse($this->service->isValidMacOsUsername('john doe'));

        // Reject quotes and shell metacharacters
        $this->assertFalse($this->service->isValidMacOsUsername('user"name'));
        $this->assertFalse($this->service->isValidMacOsUsername("user'name"));
        $this->assertFalse($this->service->isValidMacOsUsername('admin;ls'));
        $this->assertFalse($this->service->isValidMacOsUsername('admin|ls'));
        $this->assertFalse($this->service->isValidMacOsUsername('admin&ls'));
        $this->assertFalse($this->service->isValidMacOsUsername('admin$user'));
        $this->assertFalse($this->service->isValidMacOsUsername('admin`ls`'));
        $this->assertFalse($this->service->isValidMacOsUsername('admin>file'));
    }
}
