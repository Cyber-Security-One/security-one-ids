<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;
    private array $tempFiles = [];

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
        Config::set('ids.custom_log_paths', []);

        foreach ($this->tempFiles as $tempFile) {
            if (is_file($tempFile)) {
                @unlink($tempFile);
            }
        }

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
        Cache::forget('ids_custom_log_paths');

        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log');
        $this->assertFileExists($tempPath);
        $this->assertTrue(is_writable($tempPath));
        $this->tempFiles[] = $tempPath;

        file_put_contents($tempPath, 'test log content');

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify the cache state instead of mocking the Facade
        $cachedPaths = Cache::get('ids_custom_log_paths', []);
        $this->assertTrue(in_array($tempPath, $cachedPaths));
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        Cache::forget('ids_custom_log_paths');

        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log');
        $this->assertFileExists($tempPath);
        $this->assertTrue(is_writable($tempPath));
        $this->tempFiles[] = $tempPath;

        file_put_contents($tempPath, 'test log content');

        Config::set('ids.custom_log_paths', [$tempPath]);

        $initialCacheHas = Cache::has('ids_custom_log_paths');
        $initialCacheState = Cache::get('ids_custom_log_paths');

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // We avoid redundantly caching paths that are already present in the static configuration.
        // Verify the cache state remains exactly as it was prior to the operation.
        $this->assertSame($initialCacheHas, Cache::has('ids_custom_log_paths'));
        $this->assertEquals($initialCacheState, Cache::get('ids_custom_log_paths'));
    }
}
