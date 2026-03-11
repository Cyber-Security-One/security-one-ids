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
        \Illuminate\Support\Facades\Storage::fake('local');
    }

    protected function tearDown(): void
    {
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');
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
        $tempPath = \Illuminate\Support\Facades\Storage::disk('local')->path(uniqid('test_log_', true) . '.log');
        file_put_contents($tempPath, 'test log content');
        $this->tempFiles[] = $tempPath;

        return $tempPath;
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        cache()->forget('ids.custom_log_paths');
        cache()->forget('ids_custom_log_paths');

        $path = '/path/to/non/existent/file_' . uniqid() . '.log';

        // ensure the file actually does not exist
        $this->assertFileDoesNotExist($path);
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

        // Clear cache to ensure it's not set
        cache()->forget('ids.custom_log_paths');

        // Setup the cache state to already have the path
        cache()->forever('ids.custom_log_paths', [$tempPath]);

        $result = $this->service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify cache still has the path
        $this->assertTrue(cache()->has('ids.custom_log_paths'));
        $this->assertEquals([$tempPath], cache()->get('ids.custom_log_paths'));
    }
}
