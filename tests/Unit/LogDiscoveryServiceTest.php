<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = app(LogDiscoveryService::class);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'missing_' . uniqid();

        // ensure the file actually does not exist
        $this->assertFalse(is_readable($path));

        $result = $this->service->addCustomPath($path);

        $this->assertFalse($result);
    }

    public function test_add_custom_path_adds_path_and_caches_when_valid_and_not_in_config(): void
    {
        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log');
        $this->assertNotEmpty($tempPath);
        $this->assertFileExists($tempPath);

        Cache::shouldReceive('get')
            ->with('ids_custom_log_paths', [])
            ->andReturn([]);

        Cache::shouldReceive('forever')
            ->once()
            ->with('ids_custom_log_paths', [$tempPath]);

        try {
            file_put_contents($tempPath, 'test log content');

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log');
        $this->assertNotEmpty($tempPath);
        $this->assertFileExists($tempPath);

        Cache::shouldReceive('get')
            ->with('ids_custom_log_paths', [])
            ->andReturn([]);

        Cache::shouldReceive('forever')->never();

        try {
            file_put_contents($tempPath, 'test log content');

            // Set the global config for this specific test case
            Config::set('ids.custom_log_paths', [$tempPath]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }

            // Explicitly reset the config to prevent global state mutation leaking to other tests
            Config::set('ids.custom_log_paths', []);
        }
    }
}
