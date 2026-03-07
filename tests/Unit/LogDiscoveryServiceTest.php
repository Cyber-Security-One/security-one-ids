<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;
use Illuminate\Support\Facades\Cache;

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
        // Use a path in a directory that is guaranteed not to exist
        $path = sys_get_temp_dir() . '/' . uniqid('non_existent_dir_', true) . '/not_readable_log.log';

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

            // Mock the Cache facade to verify 'forever' is called
            Cache::shouldReceive('forever')
                ->once()
                ->with('ids_custom_log_paths', [$tempPath])
                ->andReturn(true);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
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

            // Mock the Cache facade to verify 'forever' is NOT called
            Cache::shouldReceive('forever')->never();

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
        } finally {
            // Clean up
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }
}
