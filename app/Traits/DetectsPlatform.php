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
        return PHP_OS_FAMILY === 'Windows';
    }

    /**
     * Determine if the current platform is macOS.
     *
     * @return bool
     */
    protected function isMac(): bool
    {
        return PHP_OS_FAMILY === 'Darwin';
    }

    /**
     * Determine if the current platform is Linux.
     *
     * @return bool
     */
    protected function isLinux(): bool
    {
        return PHP_OS_FAMILY === 'Linux';
    }

    /**
     * Get the current platform name.
     *
     * @return string
     */
    protected function getPlatformName(): string
    {
        return PHP_OS_FAMILY;
    }
}
