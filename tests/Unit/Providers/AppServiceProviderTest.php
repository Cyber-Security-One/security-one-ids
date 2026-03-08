<?php

namespace Tests\Unit\Providers;

use Tests\TestCase;
use App\Providers\AppServiceProvider;
use Illuminate\Support\Facades\Config;

class AppServiceProviderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Ensure clean state
        Config::set('ids.agent_token', 'token');
    }


    public function test_it_throws_exception_in_production_without_token()
    {
        // Mock application running in console true
        $app = \Mockery::mock($this->app)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturn(true);

        Config::set('ids.agent_token', '');
        $app['env'] = 'production';

        $provider = new AppServiceProvider($app);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('AGENT_TOKEN must be set in production environment.');

        $provider->boot();
    }

    public function test_it_does_nothing_if_in_maintenance_mode()
    {
        $app = \Mockery::mock($this->app)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturn(true);
        $app->shouldReceive('isDownForMaintenance')->andReturn(true);

        Config::set('ids.agent_token', '');
        $app['env'] = 'production';

        $provider = new AppServiceProvider($app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_in_production_web_request_without_token()
    {
        $app = \Mockery::mock($this->app)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturn(false);

        Config::set('ids.agent_token', '');
        $app['env'] = 'production';

        $provider = new AppServiceProvider($app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_if_token_is_set_in_production()
    {
        Config::set('ids.agent_token', 'valid-token');
        $this->app['env'] = 'production';

        $provider = new AppServiceProvider($this->app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_if_not_production()
    {
        Config::set('ids.agent_token', '');
        $this->app['env'] = 'local';

        $provider = new AppServiceProvider($this->app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }
}
