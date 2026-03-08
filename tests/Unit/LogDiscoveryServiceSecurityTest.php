<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;
use ReflectionClass;

class LogDiscoveryServiceSecurityTest extends TestCase
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

        $reflector = new ReflectionClass(LogDiscoveryService::class);
        $property = $reflector->getProperty('resolvedBaseDirs');
        $property->setAccessible(true);
        $property->setValue(null, null);

        parent::tearDown();
    }

    public function test_is_allowed_path()
    {
        $reflector = new ReflectionClass(LogDiscoveryService::class);
        $method = $reflector->getMethod('isAllowedPath');
        $method->setAccessible(true);

        $tempDir = sys_get_temp_dir();

        // Exact match of allowed directory should pass now
        $this->assertTrue($method->invoke($this->service, $tempDir), 'Exact directory match should be allowed.');
        $this->assertTrue($method->invoke($this->service, $tempDir . DIRECTORY_SEPARATOR . 'access.log'));

        // Ensure path outside allowed dir fails
        $this->assertFalse($method->invoke($this->service, '/etc/passwd'));

        // Similar but different boundary check shouldn't match
        $this->assertFalse($method->invoke($this->service, '/var/logo'));
    }
}
