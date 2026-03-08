<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the current platform is Windows.
     *
     * @return bool
     */
    protected function isWindows(): bool
    {
        return (defined('PHP_OS_FAMILY') && is_string(PHP_OS_FAMILY))
            ? PHP_OS_FAMILY === 'Windows'
            : DIRECTORY_SEPARATOR === '\\';
    }
}
