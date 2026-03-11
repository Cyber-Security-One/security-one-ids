<?php

declare(strict_types=1);

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
        return PHP_OS_FAMILY === 'Windows';
    }
}
