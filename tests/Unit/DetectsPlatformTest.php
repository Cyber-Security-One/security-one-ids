<?php

namespace Tests\Unit;

use App\Traits\DetectsPlatform;
use PHPUnit\Framework\TestCase;

class DetectsPlatformTest extends TestCase
{
    public function test_is_windows_returns_true_on_windows()
    {
        $class = new class {
            use DetectsPlatform;

            public function checkIsWindows(): bool
            {
                return $this->isWindows();
            }
        };

        $isWindows = PHP_OS_FAMILY === 'Windows';

        $this->assertEquals($isWindows, $class->checkIsWindows());
    }
}
