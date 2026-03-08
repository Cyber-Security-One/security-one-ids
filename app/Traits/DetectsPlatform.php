<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the current platform is Windows.
     * Intended for internal platform detection use.
     *
     * @return bool
     */
    public function detectIsWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }
}
