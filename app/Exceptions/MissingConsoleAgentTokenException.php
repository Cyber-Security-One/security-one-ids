<?php

namespace App\Exceptions;

use Exception;
use Symfony\Component\Console\Output\OutputInterface;

class MissingConsoleAgentTokenException extends Exception
{
    public function __construct(string $message = 'AGENT_TOKEN must be set in production environment.')
    {
        parent::__construct($message);
    }

    public function renderForConsole(OutputInterface $output): void
    {
        $output->writeln("<error>{$this->getMessage()}</error>");
    }
}
