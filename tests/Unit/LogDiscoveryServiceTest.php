<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;
    protected array $tempFiles = [];

    protected function setUp(): void
    {
        parent::setUp();

        // Use a real array cache to avoid issues with Cache facade and locks
        $store = new \Illuminate\Cache\ArrayStore();
        $repository = new \Illuminate\Cache\Repository($store);

        Cache::swap($repository);

        LogDiscoveryService::$migrated = false;

        $this->service = new LogDiscoveryService();
    }

    public function test_get_custom_paths_migrates_legacy_keys(): void
    {
        $path1 = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'legacy1_' . uniqid() . '.log';
        $path2 = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'legacy2_' . uniqid() . '.log';
        touch($path1);
        touch($path2);
        $this->tempFiles[] = $path1;
        $this->tempFiles[] = $path2;

        // Set up legacy keys
        Cache::forever('ids_custom_log_paths', [$path1]);
        Cache::forever('ids.custom_log_paths', [$path2]);

        Config::set('ids.custom_log_paths', []);

        $paths = $this->service->getCustomPaths();

        $this->assertContains(realpath($path1), $paths);
        $this->assertContains(realpath($path2), $paths);
        $this->assertCount(2, $paths);

        // Verify the legacy keys are deleted and new key is used
        $this->assertFalse(Cache::has('ids_custom_log_paths'));
        $this->assertFalse(Cache::has('ids.custom_log_paths'));
        $this->assertTrue(Cache::has('ids::custom_log_paths'));

        $newPaths = Cache::get('ids::custom_log_paths');
        $this->assertContains(realpath($path1), $newPaths);
        $this->assertContains(realpath($path2), $newPaths);
    }

    public function test_get_custom_paths_removes_config_paths_from_cache(): void
    {
        $legacyPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'legacy_' . uniqid() . '.log';
        $configPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'config_' . uniqid() . '.log';
        touch($legacyPath);
        touch($configPath);
        $this->tempFiles[] = $legacyPath;
        $this->tempFiles[] = $configPath;

        Cache::forever('ids_custom_log_paths', [$legacyPath, $configPath]);

        // Explicitly set the config
        Config::set('ids.custom_log_paths', [$configPath]);

        $paths = $this->service->getCustomPaths();

        // The returned paths are from cache (which should no longer have /config/path)
        $this->assertContains(realpath($legacyPath), $paths);
        $this->assertNotContains($configPath, $paths);

        $newPaths = Cache::get('ids::custom_log_paths');
        $this->assertContains(realpath($legacyPath), $newPaths);
        $this->assertNotContains($configPath, $newPaths);
    }

    public function test_add_custom_path_uses_new_key_and_avoids_duplicates(): void
    {
        // Mock a readable file
        $file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_log_' . uniqid() . '.log';
        touch($file);
        $this->tempFiles[] = $file;

        Config::set('ids.custom_log_paths', ['/config/path']);

        // Initially empty cache
        $this->assertFalse(Cache::has('ids::custom_log_paths'));

        $result = $this->service->addCustomPath($file);

        $this->assertTrue($result);

        // Verify it was added to the new key
        $this->assertTrue(Cache::has('ids::custom_log_paths'));
        $cachedPaths = Cache::get('ids::custom_log_paths');
        $this->assertContains($file, $cachedPaths);
        $this->assertNotContains('/config/path', $cachedPaths);

        // Try adding it again to verify no duplicates
        $result = $this->service->addCustomPath($file);
        $this->assertTrue($result);

        $cachedPaths = Cache::get('ids::custom_log_paths');
        $this->assertCount(1, $cachedPaths);

        unlink($file);
    }

    public function test_add_custom_path_fails_if_unreadable(): void
    {
        $nonExistentFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'missing_' . uniqid() . '.log';

        $result = $this->service->addCustomPath($nonExistentFile);

        $this->assertFalse($result);
        $this->assertFalse(Cache::has('ids::custom_log_paths'));
    }

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }

        Config::set('cache.default', 'file');

        parent::tearDown();
    }
}
