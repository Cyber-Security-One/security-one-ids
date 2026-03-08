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

        // Use array store for basic cache operations
        config(['cache.default' => 'array']);

        // Mock the lock mechanism since ArrayStore doesn't fully support it in tests out-of-the-box
        $mockLock = \Mockery::mock(\Illuminate\Contracts\Cache\Lock::class);
        $mockLock->shouldReceive('get')->andReturn(true);
        $mockLock->shouldReceive('release')->andReturn(true);

        // Instead of partial mocking the Cache manager which can be tricky,
        // we can use a partial mock on the underlying repository.
        $store = new \Illuminate\Cache\ArrayStore();
        $repository = \Mockery::mock(\Illuminate\Cache\Repository::class . '[lock]', [$store]);
        $repository->shouldReceive('lock')->andReturn($mockLock);

        Cache::swap($repository);

        $this->service = new LogDiscoveryService();
    }

    public function test_get_custom_paths_migrates_legacy_keys(): void
    {
        // Set up legacy keys
        Cache::forever('ids_custom_log_paths', ['/legacy/path/1']);
        Cache::forever('ids.custom_log_paths', ['/legacy/path/2']);

        Config::partialMock();
        Config::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->andReturn([]);

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

    public function test_get_custom_paths_merges_config_paths_with_cache(): void
    {
        Cache::forever('ids_custom_log_paths', ['/legacy/path', '/config/path']);

        // Ensure static flag is reset for test isolation
        LogDiscoveryService::$migrated = false;

        // Explicitly set the config
        Config::partialMock();
        Config::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->andReturn(['/config/path', '/another/config/path']);

        $paths = $this->service->getCustomPaths();

        // The returned paths are from cache. Since we removed the config filtering,
        // it should contain the /config/path.
        $this->assertContains('/legacy/path', $paths);
        $this->assertContains('/config/path', $paths);

        $newPaths = Cache::get('ids::custom_log_paths');
        $this->assertContains('/legacy/path', $newPaths);
        $this->assertContains('/config/path', $newPaths);
    }

    public function test_add_custom_path_uses_new_key_and_avoids_duplicates(): void
    {
        // Mock a readable file
        $file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_log_' . uniqid() . '.log';
        touch($file);
        $this->tempFiles[] = $file; // if we had a proper tearDown, but let's just use it

        Config::partialMock();
        Config::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->andReturn(['/config/path']);

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

        Config::offsetUnset('cache.default');

        parent::tearDown();
    }
}
