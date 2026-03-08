<?php

namespace App\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

class MissingAgentTokenException extends HttpException
{
    public function __construct(string $message = 'AGENT_TOKEN must be set in production environment.', \Throwable $previous = null, array $headers = [], int $code = 0)
    {
        parent::__construct(503, $message, $previous, $headers, $code);
    }
}
