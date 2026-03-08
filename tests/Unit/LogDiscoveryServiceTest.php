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
        $this->service = new LogDiscoveryService();
        cache()->forget('ids_custom_log_paths');
        cache()->forget('ids.custom_log_paths');
    }

    protected function tearDown(): void
    {
        cache()->forget('ids_custom_log_paths');
        cache()->forget('ids.custom_log_paths');
        parent::tearDown();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        // Explicitly create a non-existent path scenario by using tempnam and deleting it
        $path = tempnam(sys_get_temp_dir(), 'non_existent_log');
        unlink($path);

        $this->assertFalse(is_readable($path));

        $result = $this->service->addCustomPath($path);

        $this->assertFalse($result);
    }

    public function test_add_custom_path_adds_path_and_caches_when_valid_and_not_in_config(): void
    {
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log_');
        file_put_contents($tempPath, 'test log content');

        try {
            $this->app['config']->set('ids.custom_log_paths', []);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
            $this->assertTrue(cache()->has('ids.custom_log_paths'));
            $this->assertContains($tempPath, cache()->get('ids.custom_log_paths'));
        } finally {
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log_');
        file_put_contents($tempPath, 'test log content');

        try {
            $this->app['config']->set('ids.custom_log_paths', [$tempPath]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
            $this->assertFalse(cache()->has('ids.custom_log_paths'));
        } finally {
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_cache(): void
    {
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log_');
        file_put_contents($tempPath, 'test log content');

        try {
            $this->app['config']->set('ids.custom_log_paths', []);
            cache()->forever('ids.custom_log_paths', [$tempPath]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
            $this->assertEquals([$tempPath], cache()->get('ids.custom_log_paths'));
        } finally {
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }
}
