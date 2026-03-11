<?php

namespace Tests\Unit;

use Tests\TestCase;

class WafSyncServiceUserValidationTest extends TestCase
{
    /**
     * Test valid macOS usernames according to the regex pattern
     */
    public function test_it_allows_valid_username_via_service_behavior()
    {
        $service = app(\App\Services\WafSyncService::class);

        $this->assertTrue($service->isValidUsername('john.doe'));
        $this->assertTrue($service->isValidUsername('user_123'));
        $this->assertTrue($service->isValidUsername('admin-user'));
        $this->assertTrue($service->isValidUsername('johndoe'));
    }

    /**
     * Test invalid macOS usernames according to the regex pattern
     * These should be rejected to prevent shell injection while preserving path parsing
     */
    public function test_it_rejects_invalid_username_via_service_behavior(): void
    {
        $service = app(\App\Services\WafSyncService::class);

        $invalidUsernames = [
            'john doe',
            'user"name',
            "user'name",
            'admin;ls',
            'admin|ls',
            'admin&ls',
            'admin$user',
            'admin`ls`',
            'admin>file',
            'bad user',
            'evil$',
            '中文',
            'a/b',
        ];

        foreach ($invalidUsernames as $username) {
            $this->assertFalse(
                $service->isValidUsername($username),
                "Failed asserting that username [{$username}] is rejected by WafSyncService."
            );
        }
    }
}
