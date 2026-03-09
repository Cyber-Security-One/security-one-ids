<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the current platform is Windows.
     * Checks the operating system family at runtime and returns true only for Windows environments.
     *
     * @return bool
     */
    public function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }
}
