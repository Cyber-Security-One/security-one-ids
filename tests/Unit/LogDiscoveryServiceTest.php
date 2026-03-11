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

        // Ensure isolation by clearing state before tests run
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');
        config(['ids.custom_log_paths' => []]);

        $this->service = new LogDiscoveryService();
    }

    protected function tearDown(): void
    {
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');
        config(['ids.custom_log_paths' => []]);

        foreach ($this->tempFiles as $tempFile) {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }

        parent::tearDown();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        $path = '/path/to/non/existent/file.log';

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

        try {
            // Setup config with empty paths initially
            config(['ids.custom_log_paths' => []]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify the actual cache state
            $this->assertEquals([$tempPath], cache()->get('ids.custom_log_paths'));
        } finally {
            // Clean up
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_add_custom_path_caches_path_even_when_path_already_in_config(): void
    {
        if (!is_writable(sys_get_temp_dir())) {
            $this->markTestSkipped('Temp directory is not writable');
        }

        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        $this->tempFiles[] = $tempPath;
        file_put_contents($tempPath, 'test log content');

        try {
            // Setup config with the path already in it
            config(['ids.custom_log_paths' => [$tempPath]]);

            // Clear cache to ensure it's not set
            cache()->forget('ids.custom_log_paths');

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);

            // Verify the path is cached and accessible via getCustomPaths()
            $this->assertEquals([$tempPath], $this->service->getCustomPaths());
        } finally {
            // Clean up
            if (file_exists($tempPath)) {
                unlink($tempPath);
            }
        }
    }
}
