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
        // Use the array driver to isolate cache state per test
        config(['cache.default' => 'array']);
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
        $this->assertIsString($tempPath);
        $this->assertFileExists($tempPath);

        $originalCustomPaths = config('ids.custom_log_paths', []);
        Config::set('ids.custom_log_paths', []);

        $lockMock = \Mockery::mock(\Illuminate\Contracts\Cache\Lock::class);
        $lockMock->shouldReceive('get')->andReturn(true);
        $lockMock->shouldReceive('release');

        Cache::shouldReceive('lock')
            ->with('lock::ids::custom_log_paths_add', 30)
            ->andReturn($lockMock);

        Cache::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->andReturn([]);

        Cache::shouldReceive('forever')
            ->once()
            ->with('ids.custom_log_paths', [$tempPath]);

        try {
            file_put_contents($tempPath, 'test log content');

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
        } finally {
            if (isset($tempPath) && is_file($tempPath)) {
                unlink($tempPath);
            }

            Config::set('ids.custom_log_paths', $originalCustomPaths);
        }
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log');
        $this->assertIsString($tempPath);
        $this->assertFileExists($tempPath);

        $lockMock = \Mockery::mock(\Illuminate\Contracts\Cache\Lock::class);
        $lockMock->shouldReceive('get')->andReturn(true);
        $lockMock->shouldReceive('release');

        Cache::shouldReceive('lock')
            ->with('lock::ids::custom_log_paths_add', 30)
            ->andReturn($lockMock);

        Cache::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->andReturn([]);

        Cache::shouldReceive('forever')->never();

        $originalCustomPaths = config('ids.custom_log_paths', []);

        try {
            file_put_contents($tempPath, 'test log content');

            // Set the global config for this specific test case
            Config::set('ids.custom_log_paths', [$tempPath]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
        } finally {
            if (isset($tempPath) && is_file($tempPath)) {
                unlink($tempPath);
            }

            // Restore original config to avoid leaking global state
            Config::set('ids.custom_log_paths', $originalCustomPaths);
        }
    }
}
