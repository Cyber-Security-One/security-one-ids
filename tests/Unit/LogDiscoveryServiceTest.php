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

    public function test_add_custom_path_handles_lock_timeout_gracefully(): void
    {
        $tempPath = $this->createTempLogFile();
        config(['ids.custom_log_paths' => []]);
        cache()->forget('ids.custom_log_paths');

        // Simulate another process holding the lock indefinitely
        $lock = cache()->lock('lock.ids.custom_log_paths', 10);
        $lock->get();

        // We expect an exception since the cache driver does not support blocking in arrays
        // or we mock the timeout by catching it in the service
        // Since we are using the array cache driver in testing which supports locks but not blocking accurately,
        // we'll simulate the service returning false due to timeout and path not added
        $startTime = microtime(true);
        $result = $this->service->addCustomPath($tempPath);
        $endTime = microtime(true);

        // It should return false because the lock is held and the path wasn't added by the other process
        $this->assertFalse($result);

        // Ensure it blocked for some time (e.g. up to 5 seconds depending on implementation limits)
        // With ArrayStore, block timeout works synchronously in a loop.
        $this->assertGreaterThan(4.5, $endTime - $startTime);

        $lock->release();
    }
}
