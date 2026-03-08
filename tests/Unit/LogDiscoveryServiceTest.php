<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;

    protected function setUp(): void
    {
        parent::setUp();

        // Use a real array cache to avoid issues with Cache facade and locks
        $store = new \Illuminate\Cache\ArrayStore();
        $repository = new \Illuminate\Cache\Repository($store);

        // The ArrayStore doesn't natively support locks in older Laravel without the Lockable cache interface,
        // but Laravel's ArrayStore usually supports locks. If not, we might need a mocked lock.
        // Actually, let's just use Cache facade with a mock or fully mocked lock.
        Cache::swap($repository);

        $this->service = new LogDiscoveryService();
    }

    public function test_get_custom_paths_migrates_legacy_keys(): void
    {
        // Set up legacy keys
        Cache::forever('ids_custom_log_paths', ['/legacy/path/1']);
        Cache::forever('ids.custom_log_paths', ['/legacy/path/2']);

        Config::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->andReturn([]);
        Config::makePartial();

        $paths = $this->service->getCustomPaths();

        $this->assertContains('/legacy/path/1', $paths);
        $this->assertContains('/legacy/path/2', $paths);
        $this->assertCount(2, $paths);

        // Verify the legacy keys are deleted and new key is used
        $this->assertFalse(Cache::has('ids_custom_log_paths'));
        $this->assertFalse(Cache::has('ids.custom_log_paths'));
        $this->assertTrue(Cache::has('ids::custom_log_paths'));

        $newPaths = Cache::get('ids::custom_log_paths');
        $this->assertContains('/legacy/path/1', $newPaths);
        $this->assertContains('/legacy/path/2', $newPaths);
    }

    public function test_get_custom_paths_removes_config_paths_from_cache(): void
    {
        Cache::forever('ids_custom_log_paths', ['/legacy/path', '/config/path']);

        // Explicitly set the config
        Config::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->andReturn(['/config/path']);
        Config::makePartial();

        $paths = $this->service->getCustomPaths();

        // The returned paths are from cache (which should no longer have /config/path)
        $this->assertContains('/legacy/path', $paths);
        $this->assertNotContains('/config/path', $paths);

        $newPaths = Cache::get('ids::custom_log_paths');
        $this->assertContains('/legacy/path', $newPaths);
        $this->assertNotContains('/config/path', $newPaths);
    }

    public function test_add_custom_path_uses_new_key_and_avoids_duplicates(): void
    {
        // Mock a readable file
        $file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_log_' . uniqid() . '.log';
        touch($file);
        $this->tempFiles[] = $file; // if we had a proper tearDown, but let's just use it

        Config::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->andReturn(['/config/path']);
        Config::makePartial();

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

    protected array $tempFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }

        Config::offsetUnset('cache.default');

        parent::tearDown();
    }
}
