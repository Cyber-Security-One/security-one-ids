<?php

namespace Tests\Unit\Providers;

use Tests\TestCase;
use App\Providers\AppServiceProvider;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Psr\Log\LoggerInterface;
use Mockery;

class AppServiceProviderTest extends TestCase
{
    private Application $appMock;
    private LoggerInterface $loggerMock;
    private ConfigRepository $configMock;
    private AppServiceProvider $provider;

    protected function setUp(): void
    {
        parent::setUp();

        $this->appMock = Mockery::mock(Application::class);
        $this->loggerMock = Mockery::mock(LoggerInterface::class);
        $this->configMock = Mockery::mock(ConfigRepository::class);

        $this->provider = new AppServiceProvider($this->appMock);
    }

    public function test_it_throws_exception_in_production_without_token_in_web_request()
    {
        $this->configMock->shouldReceive('get')->with('ids.agent_token', '')->andReturn('');

        $this->appMock->shouldReceive('environment')->with('production')->andReturn(true);
        $this->appMock->shouldReceive('runningInConsole')->andReturn(false);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('AGENT_TOKEN must be set in production environment.');

        $this->provider->boot($this->appMock, $this->loggerMock, $this->configMock);
    }

    public function test_it_logs_warning_in_production_without_token_in_console()
    {
        $this->configMock->shouldReceive('get')->with('ids.agent_token', '')->andReturn('');

        $this->appMock->shouldReceive('environment')->with('production')->andReturn(true);
        $this->appMock->shouldReceive('runningInConsole')->andReturn(true);

        $this->loggerMock->shouldReceive('warning')
            ->once()
            ->with('AGENT_TOKEN is empty in production environment during console command. This may lead to an insecure configuration cache.');

        $this->provider->boot($this->appMock, $this->loggerMock, $this->configMock);
    }

    public function test_it_does_nothing_if_token_is_set_in_production()
    {
        $this->configMock->shouldReceive('get')->with('ids.agent_token', '')->andReturn('valid-token');

        $this->appMock->shouldReceive('environment')->with('production')->andReturn(true);

        $this->loggerMock->shouldReceive('warning')->never();

        $this->provider->boot($this->appMock, $this->loggerMock, $this->configMock);

        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_if_not_production()
    {
        $this->configMock->shouldReceive('get')->with('ids.agent_token', '')->andReturn('');

        $this->appMock->shouldReceive('environment')->with('production')->andReturn(false);

        $this->loggerMock->shouldReceive('warning')->never();

        $this->provider->boot($this->appMock, $this->loggerMock, $this->configMock);

        $this->assertTrue(true); // Reached without exception
    }
}
