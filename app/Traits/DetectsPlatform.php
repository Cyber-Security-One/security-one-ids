<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Cache the platform check result.
     *
     * @var bool|null
     */
    private ?bool $isWindowsCached = null;

    /**
     * Determine if the current platform is Windows.
     *
     * @return bool
     */
    protected function isWindows(): bool
    {
        if ($this->isWindowsCached !== null) {
            return $this->isWindowsCached;
        }

        if (defined('PHP_OS_FAMILY')) {
            $this->isWindowsCached = PHP_OS_FAMILY === 'Windows';
        } else {
            $this->isWindowsCached = stripos(PHP_OS, 'WIN') === 0;
        }

        return $this->isWindowsCached;
    }
}
