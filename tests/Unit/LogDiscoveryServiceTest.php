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
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');
        \Illuminate\Support\Facades\Config::set('ids.custom_log_paths', []);
    }

    protected function tearDown(): void
    {
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');

        foreach ($this->tempFiles as $tempFile) {
            if (file_exists($tempFile)) {
                unlink($tempFile);
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
        $this->assertFalse(cache()->has('ids.custom_log_paths'));
    }

    public function test_add_custom_path_adds_path_and_caches_when_valid_and_not_in_config(): void
    {
        if (!is_writable(sys_get_temp_dir())) {
            $this->markTestSkipped('Temp directory is not writable');
        }

        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        $this->tempFiles[] = $tempPath;
        file_put_contents($tempPath, 'test log content');

        // Setup config with empty paths initially
        \Illuminate\Support\Facades\Config::set('ids.custom_log_paths', []);

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify observable behavior (cache state)
        $this->assertEquals([$tempPath], $this->service->getCustomPaths());

        // Verify config updated
        $this->assertEquals([$tempPath], config('ids.custom_log_paths'));
    }

    public function test_add_custom_path_returns_true_without_caching_again_when_path_already_cached(): void
    {
        if (!is_writable(sys_get_temp_dir())) {
            $this->markTestSkipped('Temp directory is not writable');
        }

        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        $this->tempFiles[] = $tempPath;
        file_put_contents($tempPath, 'test log content');

        // Setup cache with the path already in it
        cache()->forever('ids.custom_log_paths', [$tempPath]);

        // Ensure config is empty so it gets updated
        \Illuminate\Support\Facades\Config::set('ids.custom_log_paths', []);

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify config gets updated
        $this->assertEquals([$tempPath], config('ids.custom_log_paths'));

        // Verify cache observable behavior
        $this->assertEquals([$tempPath], $this->service->getCustomPaths());
    }
}
