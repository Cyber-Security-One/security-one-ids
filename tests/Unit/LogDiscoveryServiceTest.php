<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new LogDiscoveryService();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        $path = '/path/to/non/existent/file.log';

        // ensure the file actually does not exist
        $this->assertFalse(is_readable($path));

        $result = $this->service->addCustomPath($path);

        $this->assertFalse($result);
    }

    public function test_add_custom_path_adds_path_and_caches_when_valid_and_not_in_config(): void
    {
        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        file_put_contents($tempPath, 'test log content');

        try {
            // Setup config with empty paths initially
            config(['ids.custom_log_paths' => []]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify the actual cache state
            $this->assertEquals([$tempPath], cache()->get('ids.custom_log_paths'));
        } finally {
            // Clean up
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        file_put_contents($tempPath, 'test log content');

        try {
            // Setup config with the path already in it
            config(['ids.custom_log_paths' => [$tempPath]]);

            // Clear cache to ensure it's not set
            cache()->forget('ids.custom_log_paths');

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify cache is still null since it was already in config
            $this->assertNull(cache()->get('ids.custom_log_paths'));
        } finally {
            // Clean up
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }
}
