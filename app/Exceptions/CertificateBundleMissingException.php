<?php

namespace App\Exceptions;

use RuntimeException;

class CertificateBundleMissingException extends RuntimeException
{
    public function __construct(string $path = '', int $code = 0, \Throwable $previous = null)
    {
        $message = "CA certificate bundle is missing, refusing to disable TLS verification.";
        if ($path) {
            $message .= " (Expected at: {$path})";
        }
        parent::__construct($message, $code, $previous);
    }
}
