<?php

namespace App\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

class MissingAgentTokenException extends HttpException
{
    public function __construct(string $message = 'AGENT_TOKEN must be explicitly configured in production.', \Throwable $previous = null, int $code = 0, array $headers = [])
    {
        parent::__construct(503, $message, $previous, $headers, $code);
    }
}
