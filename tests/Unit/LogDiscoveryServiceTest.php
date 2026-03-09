<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;
    private array $tempFiles = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new LogDiscoveryService();
        cache()->forget('ids::custom_log_paths');
        cache()->forget('ids_custom_log_paths');
        cache()->forget('ids.custom_log_paths');
    }

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $tempFile) {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
        parent::tearDown();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        // Explicitly create a non-existent path scenario by using tempnam and deleting it
        $path = tempnam(sys_get_temp_dir(), 'non_existent_log');
        $this->tempFiles[] = $path;
        unlink($path);

        // Tiny sleep to ensure filesystem reflects deletion accurately
        usleep(1000);
        clearstatcache(true, $path);

        $this->assertFalse(file_exists($path));
        $this->assertFalse(is_readable($path));

        $result = $this->service->addCustomPath($path);

        $this->assertFalse($result);
    }

    public function test_add_custom_path_adds_path_and_caches_when_valid_and_not_in_config(): void
    {
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log_');
        $this->tempFiles[] = $tempPath;
        file_put_contents($tempPath, 'test log content');

        $this->app['config']->set('ids.custom_log_paths', []);

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);
        $this->assertTrue(cache()->has('ids.custom_log_paths'));
        $this->assertContains($tempPath, cache()->get('ids.custom_log_paths'));
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log_');
        $this->tempFiles[] = $tempPath;
        file_put_contents($tempPath, 'test log content');

        $this->app['config']->set('ids.custom_log_paths', [$tempPath]);

        // Explicitly ensure cache is empty before the operation, as the service
        // might lazy load config paths into cache on startup or prior accesses.
        cache()->forget('ids.custom_log_paths');

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Because the path is in the config, the service short-circuits and never reads the cache
        // or initializes it. Therefore, the cache key should genuinely not exist.
        $this->assertFalse(cache()->has('ids.custom_log_paths'));
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_cache(): void
    {
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log_');
        $this->tempFiles[] = $tempPath;
        file_put_contents($tempPath, 'test log content');

        $this->app['config']->set('ids.custom_log_paths', []);
        cache()->forever('ids.custom_log_paths', [$tempPath]);

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);
        $this->assertEquals([$tempPath], cache()->get('ids.custom_log_paths'));
    }
}
