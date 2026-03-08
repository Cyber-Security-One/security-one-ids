<?php

namespace Tests\Unit;

use Tests\TestCase;
use App\Services\LogDiscoveryService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;

class LogDiscoveryServiceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['cache.default' => 'array']);
        Cache::driver('array')->clear();
    }

    public function testGetCustomPathsMigratesLegacyKeys()
    {
        $service = app(LogDiscoveryService::class);
        LogDiscoveryService::$migrated = false;

        Cache::put('ids_custom_log_paths', ['/path/one']);
        Cache::put('ids::custom_log_paths', ['/path/three']);

        $paths = $service->getCustomPaths();

        $this->assertEquals(['/path/one', '/path/three'], $paths);

        $this->assertFalse(Cache::has('ids_custom_log_paths'));

        $this->assertEquals(['/path/one', '/path/three'], Cache::get('ids::custom_log_paths'));
    }

    public function testGetCustomPathsWithoutLegacyKeys()
    {
        $service = app(LogDiscoveryService::class);
        LogDiscoveryService::$migrated = false;

        Cache::put('ids::custom_log_paths', ['/path/only']);

        $paths = $service->getCustomPaths();

        $this->assertEquals(['/path/only'], $paths);
        $this->assertEquals(['/path/only'], Cache::get('ids::custom_log_paths'));
    }

    public function testAddCustomPath()
    {
        $service = app(LogDiscoveryService::class);

        // Use standard config mock pattern so it handles cache locks as well
        // We do not mock it directly this time as we may break cache lock dependencies.
        config(['ids.custom_log_paths' => []]);

        $testPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_log_' . uniqid() . '.log';
        file_put_contents($testPath, 'test');

        try {
            $service->addCustomPath($testPath);

            $paths = Cache::get('ids::custom_log_paths');

            $this->assertIsArray($paths);
            $this->assertContains($testPath, $paths);
        } finally {
            unlink($testPath);
        }
    }
}
