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
        $this->service = app(LogDiscoveryService::class);
        // Ensure we start with a clean state without modifying global config across tests
        Cache::forget('ids_custom_log_paths');
    }

    protected function tearDown(): void
    {
        Cache::forget('ids_custom_log_paths');
        parent::tearDown();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'missing_' . uniqid();

        // ensure the file actually does not exist
        $this->assertFileDoesNotExist($path);
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

        try {
            file_put_contents($tempPath, 'test log content');

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify the cache state instead of mocking the Facade
            $cachedPaths = Cache::get('ids_custom_log_paths', []);
            $this->assertTrue(in_array($tempPath, $cachedPaths));
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

        try {
            file_put_contents($tempPath, 'test log content');

            // To isolate config modification without polluting global state across tests,
            // we use Laravel's internal config array mutation which is automatically reset by TestCase after the test
            \Illuminate\Support\Facades\Config::set('ids.custom_log_paths', [$tempPath]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify it was not added to the cache, since it was already in the config
            $cachedPaths = Cache::get('ids_custom_log_paths', []);
            $this->assertFalse(in_array($tempPath, $cachedPaths));
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }
}
