<?php

namespace App\Exceptions;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Console\Output\OutputInterface;
use Illuminate\Contracts\Console\Kernel;
use Symfony\Component\Console\Exception\CommandNotFoundException;

class MissingAgentTokenException extends HttpException
{
    public function __construct(string $message = 'AGENT_TOKEN must be set in production environment.', \Throwable $previous = null, array $headers = [], int $code = 0)
    {
        parent::__construct(503, $message, $previous, $headers, $code);
    }

    /**
     * Render the exception to the console.
     */
    public function renderForConsole(OutputInterface $output): void
    {
        $output->writeln('');
        $output->writeln('  <bg=red;fg=white> ERROR </> <fg=red>' . $this->getMessage() . '</>');
        $output->writeln('');
    }
}
