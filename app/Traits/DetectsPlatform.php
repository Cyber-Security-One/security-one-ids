<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the current platform is Windows.
     *
     * @return bool
     */
    public function isWindows(): bool
    {
        return defined('PHP_OS_FAMILY')
            ? PHP_OS_FAMILY === 'Windows'
            : stripos(PHP_OS, 'WIN') === 0;
    }
}
