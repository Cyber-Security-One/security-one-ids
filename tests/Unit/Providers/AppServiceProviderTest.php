<?php

namespace Tests\Unit\Providers;

use Tests\TestCase;
use App\Providers\AppServiceProvider;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class AppServiceProviderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function tearDown(): void
    {
        Config::offsetUnset('ids.agent_token');
        parent::tearDown();
    }


    public function test_it_throws_exception_in_production_without_token_in_web_request()
    {
        $appMock = \Mockery::spy(\Illuminate\Foundation\Application::class);
        $appMock->shouldReceive('runningInConsole')->andReturn(false);
        $appMock->shouldReceive('environment')->with('production')->andReturn(true);

        Config::set('ids.agent_token', '');

        $provider = new AppServiceProvider($appMock);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('AGENT_TOKEN must be set in production environment.');

        $provider->boot();
    }

    public function test_it_logs_warning_in_production_without_token_in_console()
    {
        $appMock = \Mockery::spy(\Illuminate\Foundation\Application::class);
        $appMock->shouldReceive('runningInConsole')->andReturn(true);
        $appMock->shouldReceive('environment')->with('production')->andReturn(true);

        Config::set('ids.agent_token', '');

        Log::shouldReceive('warning')
            ->once()
            ->with('AGENT_TOKEN is empty in production environment during console command. This may lead to an insecure configuration cache.');

        $provider = new AppServiceProvider($appMock);

        $provider->boot();
    }

    public function test_it_does_nothing_if_token_is_set_in_production()
    {
        $appMock = \Mockery::spy(\Illuminate\Foundation\Application::class);
        $appMock->shouldReceive('environment')->with('production')->andReturn(true);

        Config::set('ids.agent_token', 'valid-token');

        Log::shouldReceive('warning')->never();

        $provider = new AppServiceProvider($appMock);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_if_not_production()
    {
        $appMock = \Mockery::spy(\Illuminate\Foundation\Application::class);
        $appMock->shouldReceive('environment')->with('production')->andReturn(false);

        Config::set('ids.agent_token', '');

        Log::shouldReceive('warning')->never();

        $provider = new AppServiceProvider($appMock);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }
}
