<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the current platform is Windows.
     *
     * @return bool
     */
    private function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }
}
