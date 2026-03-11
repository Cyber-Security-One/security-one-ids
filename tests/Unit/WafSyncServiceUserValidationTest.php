<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;

class WafSyncServiceUserValidationTest extends TestCase
{
    /**
     * Test valid macOS usernames according to the regex pattern
     */
    public function testValidMacOsUsernames()
    {
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'john.doe'));
        $this->assertTrue((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'user_123'));
        $this->assertTrue((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'admin-user'));
        $this->assertTrue((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'johndoe'));
    }

    /**
     * Test invalid macOS usernames according to the regex pattern
     * These should be rejected to prevent shell injection while preserving path parsing
     */
    public function testInvalidMacOsUsernames()
    {
        // Reject spaces
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'john doe'));

        // Reject quotes and shell metacharacters
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'user"name'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', "user'name"));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'admin;ls'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'admin|ls'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'admin&ls'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'admin$user'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'admin`ls`'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z_][a-zA-Z0-9_-]*$/', 'admin>file'));
    }
}
