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
        config(['cache.default' => 'array']);
        $this->service = new LogDiscoveryService();
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');
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
        $this->assertFileDoesNotExist($path);

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
        config(['ids.custom_log_paths' => []]);

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify the actual cache state
        $this->assertEquals([$tempPath], cache()->get('ids.custom_log_paths'));
    }

    public function test_add_custom_path_adds_to_cache_even_if_in_config(): void
    {
        if (!is_writable(sys_get_temp_dir())) {
            $this->markTestSkipped('Temp directory is not writable');
        }

        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        $this->tempFiles[] = $tempPath;
        file_put_contents($tempPath, 'test log content');

        // Setup config with the path already in it
        config(['ids.custom_log_paths' => [$tempPath]]);

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify cache is updated regardless of config
        $this->assertEquals([$tempPath], cache()->get('ids.custom_log_paths'));
    }
}
