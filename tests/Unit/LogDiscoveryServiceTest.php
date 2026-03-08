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
        LogDiscoveryService::$migrated = false;
        LogDiscoveryService::$resolvingFallback = false;
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
        LogDiscoveryService::$migrated = false;
        LogDiscoveryService::$resolvingFallback = false;
        cache()->forget('ids::custom_log_paths');
        cache()->forget('ids_custom_log_paths');
        cache()->forget('ids.custom_log_paths');
        parent::tearDown();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        // Use a genuinely non-existent path to reliably test unreadable handling
        // without relying on filesystem timing from immediate file deletion
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'non_existent_log_' . uniqid('', true);

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

    public function test_add_custom_path_syncs_cache_when_path_already_in_config(): void
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
        $this->assertTrue(cache()->has('ids.custom_log_paths'));
        $this->assertContains($tempPath, cache()->get('ids.custom_log_paths'));
    }

    public function test_add_custom_path_syncs_cache_when_path_already_in_cache(): void
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
