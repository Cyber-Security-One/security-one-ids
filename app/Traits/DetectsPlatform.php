<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the application is running on Windows.
     *
     * @return bool
     */
    public function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }
}
