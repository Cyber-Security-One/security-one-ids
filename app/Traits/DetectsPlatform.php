<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the application is running on a Windows platform.
     *
     * @return bool
     */
    public function detectIsWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }
}
