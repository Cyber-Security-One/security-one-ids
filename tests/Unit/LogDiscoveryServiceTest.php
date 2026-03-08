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
        cache()->forget('ids.custom_log_paths');
        config(['ids.custom_log_paths' => []]);
        $this->service = new LogDiscoveryService();
    }

    protected function tearDown(): void
    {
        cache()->forget('ids.custom_log_paths');
        config(['ids.custom_log_paths' => []]);

        foreach ($this->tempFiles as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }

        parent::tearDown();
    }

    private function createTempLogFile(): string
    {
        if (!is_writable(sys_get_temp_dir())) {
            $this->markTestSkipped('Temp directory is not writable');
        }

        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        if ($tempPath === false) {
            $this->fail('Failed to create temporary file.');
        }

        file_put_contents($tempPath, 'test log content');
        $this->tempFiles[] = $tempPath;

        return $tempPath;
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
        $tempPath = $this->createTempLogFile();

        // Setup config with empty paths initially
        config(['ids.custom_log_paths' => []]);

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify the actual cache state
        $this->assertEquals([$tempPath], cache()->get('ids.custom_log_paths'));
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        $tempPath = $this->createTempLogFile();

        // Setup config with the path already in it
        config(['ids.custom_log_paths' => [$tempPath]]);

        // Clear cache to ensure it's not set
        cache()->forget('ids.custom_log_paths');

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify cache is not set since it was already in config
        $this->assertFalse(cache()->has('ids.custom_log_paths'));
    }

    public function test_add_custom_path_is_idempotent_when_path_in_both_config_and_cache(): void
    {
        $tempPath = $this->createTempLogFile();

        // Setup config with the path already in it
        config(['ids.custom_log_paths' => [$tempPath]]);

        // Also mock the cache to already have it
        cache()->forever('ids.custom_log_paths', [$tempPath]);

        // Attempt to add it again
        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify it didn't do something unexpected
        $cachedPaths = cache()->get('ids.custom_log_paths');
        $this->assertEquals([$tempPath], $cachedPaths);
        $this->assertCount(1, $cachedPaths);
    }
}
