<?php

namespace App\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;

class MissingAgentTokenException extends HttpException
{
    public function __construct(string $message = 'The AGENT_TOKEN environment variable must be explicitly configured in production for API access.', \Throwable $previous = null, int $code = 0, array $headers = [])
    {
        parent::__construct(401, $message, $previous, $headers, $code);
    }
}
