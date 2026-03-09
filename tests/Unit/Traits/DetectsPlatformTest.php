<?php

namespace Tests\Unit\Traits;

use App\Traits\DetectsPlatform;
use PHPUnit\Framework\TestCase;

class DetectsPlatformTest extends TestCase
{
    /**
     * Test the isWindows method matches the PHP_OS_FAMILY constant.
     *
     * @return void
     */
    public function testIsWindowsReturnsCorrectBoolean()
    {
        // Create an anonymous class that uses the trait to test it
        $class = new class {
            use DetectsPlatform;
        };

        $expected = PHP_OS_FAMILY === 'Windows';

        $this->assertSame($expected, $class->isWindows());
    }
}
