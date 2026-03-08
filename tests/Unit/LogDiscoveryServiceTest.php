<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;
use Illuminate\Support\Facades\Cache;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;
    private string $cacheKey;
    private string $configKey;
    private string $legacyCacheKey;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = app(LogDiscoveryService::class);

        // Generate unique keys for each test instance
        $uniqueSuffix = uniqid('test_', true);
        $this->cacheKey = 'ids.custom_log_paths.' . $uniqueSuffix;
        $this->configKey = 'ids.custom_log_paths.' . $uniqueSuffix;
        $this->legacyCacheKey = 'ids_custom_log_paths_' . $uniqueSuffix;

        // Inject the unique keys into the service
        $this->service->setCacheKey($this->cacheKey);
        $this->service->setConfigKey($this->configKey);
        $this->service->setLegacyCacheKey($this->legacyCacheKey);
    }

    protected function tearDown(): void
    {
        Cache::forget($this->cacheKey);
        Cache::forget($this->legacyCacheKey);
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
        $this->assertNotFalse($tempPath);

        try {
            file_put_contents($tempPath, 'test log content');

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify the cache state instead of mocking the Facade
            $cachedPaths = Cache::get($this->cacheKey, []);
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
        $this->assertNotFalse($tempPath);

        try {
            file_put_contents($tempPath, 'test log content');

            // To isolate config modification without polluting global state across tests,
            // we use Laravel's internal config array mutation which is automatically reset by TestCase after the test
            $this->app['config']->set($this->configKey, [$tempPath]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify it was not added to the cache, since it was already in the config
            $cachedPaths = Cache::get($this->cacheKey, []);
            $this->assertFalse(in_array($tempPath, $cachedPaths));
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_get_custom_paths_migrates_legacy_cache_key(): void
    {
        // Setup legacy cache key with some data
        $legacyPaths = ['/var/log/custom/legacy.log'];
        Cache::forever($this->legacyCacheKey, $legacyPaths);

        // Ensure new cache key is empty initially
        $this->assertFalse(Cache::has($this->cacheKey));

        // Call getCustomPaths which should trigger the migration
        $paths = $this->service->getCustomPaths();

        $this->assertEquals($legacyPaths, $paths);

        // Assert migration was successful
        $this->assertTrue(Cache::has($this->cacheKey));
        $this->assertEquals($legacyPaths, Cache::get($this->cacheKey));
        $this->assertFalse(Cache::has($this->legacyCacheKey));
    }
}
