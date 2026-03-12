<?php

namespace Tests\Unit;

use Tests\TestCase;

class WafSyncServiceUserValidationTest extends TestCase
{
    /**
     * Test valid macOS usernames according to the regex pattern
     */
    public function testValidMacOsUsernames()
    {
        // Use reflection to bypass constructor which reads .env
        $reflection = new \ReflectionClass(\App\Services\WafSyncService::class);
        $service = $reflection->newInstanceWithoutConstructor();

        $this->assertTrue($service->isValidMacOsUsername('john.doe'));
        $this->assertTrue($service->isValidMacOsUsername('user_123'));
        $this->assertTrue($service->isValidMacOsUsername('admin-user'));
        $this->assertTrue($service->isValidMacOsUsername('johndoe'));
    }

    /**
     * Test invalid macOS usernames according to the regex pattern
     * These should be rejected to prevent shell injection while preserving path parsing
     */
    public function testInvalidMacOsUsernames()
    {
        $reflection = new \ReflectionClass(\App\Services\WafSyncService::class);
        $service = $reflection->newInstanceWithoutConstructor();

        // Reject spaces
        $this->assertFalse($service->isValidMacOsUsername('john doe'));

        // Reject leading dash to prevent command injection
        $this->assertFalse($service->isValidMacOsUsername('-admin'));
        $this->assertFalse($service->isValidMacOsUsername('--root'));

        // Reject quotes and shell metacharacters
        $this->assertFalse($service->isValidMacOsUsername('user"name'));
        $this->assertFalse($service->isValidMacOsUsername("user'name"));
        $this->assertFalse($service->isValidMacOsUsername('admin;ls'));
        $this->assertFalse($service->isValidMacOsUsername('admin|ls'));
        $this->assertFalse($service->isValidMacOsUsername('admin&ls'));
        $this->assertFalse($service->isValidMacOsUsername('admin$user'));
        $this->assertFalse($service->isValidMacOsUsername('admin`ls`'));
        $this->assertFalse($service->isValidMacOsUsername('admin>file'));
    }
}
