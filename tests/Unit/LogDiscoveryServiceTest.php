<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;

    protected function setUp(): void
    {
        parent::setUp();
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');
        $this->service = new LogDiscoveryService();
    }

    protected function tearDown(): void
    {
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');
        parent::tearDown();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'missing_' . uniqid();

        // ensure the file actually does not exist
        $this->assertFalse(is_readable($path));
        $this->assertFalse(file_exists($path));

        $result = $this->service->addCustomPath($path);

        $this->assertFalse($result);
        $this->assertFalse(cache()->has('ids.custom_log_paths'));
    }

    public function test_add_custom_path_adds_path_and_caches_when_valid_and_not_in_config(): void
    {
        if (!is_writable(sys_get_temp_dir())) {
            $this->markTestSkipped('Temp directory is not writable');
        }

        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        file_put_contents($tempPath, 'test log content');

        try {
            // Setup config with empty paths initially
            $this->app['config']->set('ids.custom_log_paths', []);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify the actual cache state
            $this->assertEquals([realpath($tempPath)], cache()->get('ids.custom_log_paths'));
        } finally {
            // Clean up
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        if (!is_writable(sys_get_temp_dir())) {
            $this->markTestSkipped('Temp directory is not writable');
        }

        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        file_put_contents($tempPath, 'test log content');

        try {
            // Setup config with the path already in it
            $this->app['config']->set('ids.custom_log_paths', [$tempPath]);

            // Clear cache to ensure it's not set
            cache()->forget('ids.custom_log_paths');

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify cache is not set since it was already in config
            $this->assertFalse(cache()->has('ids.custom_log_paths'));
        } finally {
            // Clean up
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_get_custom_paths_migrates_legacy_cache_key(): void
    {
        $legacyPaths = ['/var/log/custom1.log', '/var/log/custom2.log'];
        cache()->forever('ids_custom_log_paths', $legacyPaths);

        // Ensure new key is empty
        $this->assertFalse(cache()->has('ids.custom_log_paths'));

        $paths = $this->service->getCustomPaths();

        $this->assertEquals($legacyPaths, $paths);

        // Verify migration
        $this->assertTrue(cache()->has('ids.custom_log_paths'));
        $this->assertEquals($legacyPaths, cache()->get('ids.custom_log_paths'));
        $this->assertFalse(cache()->has('ids_custom_log_paths'));
    }
}
