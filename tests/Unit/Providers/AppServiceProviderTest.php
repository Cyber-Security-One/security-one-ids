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

    protected function tearDown(): void
    {
        $this->artisan('up');
        parent::tearDown();
    }

    public function test_it_throws_exception_in_production_console_command_without_token()
    {
        Config::set('ids.agent_token', '');
        $this->app['env'] = 'production';

        // The application runs in console by default during tests.
        // We register the service provider to run boot()
        $this->app->register(AppServiceProvider::class);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('AGENT_TOKEN must be set in production environment.');

        // Dispatch the CommandStarting event to trigger the validation logic
        $this->app['events']->dispatch(new \Illuminate\Console\Events\CommandStarting(
            'test:command',
            new \Symfony\Component\Console\Input\ArrayInput([]),
            new \Symfony\Component\Console\Output\NullOutput()
        ));
    }

    public function test_it_does_nothing_if_in_maintenance_mode()
    {
        Config::set('ids.agent_token', '');
        $this->app['env'] = 'production';

        // Simulate maintenance mode safely
        $this->artisan('down');

        $this->app->register(AppServiceProvider::class);

        // Dispatch the CommandStarting event
        $this->app['events']->dispatch(new \Illuminate\Console\Events\CommandStarting(
            'test:command',
            new \Symfony\Component\Console\Input\ArrayInput([]),
            new \Symfony\Component\Console\Output\NullOutput()
        ));

        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_in_production_web_request_without_token()
    {
        Config::set('ids.agent_token', '');
        $this->app['env'] = 'production';

        // In a true web request, runningInConsole() is false, so boot() won't register CLI events.
        // We verify that calling boot() with a mock where runningInConsole() is false
        // safely does nothing and registers no events.

        $app = \Mockery::mock($this->app)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturn(false);

        $provider = new AppServiceProvider($app);

        $provider->boot(
            $app,
            $this->app->make(\Illuminate\Contracts\Config\Repository::class),
            $this->app->make(\Illuminate\Contracts\Events\Dispatcher::class)
        );

        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_if_token_is_set_in_production()
    {
        Config::set('ids.agent_token', 'valid-token');
        $this->app['env'] = 'production';

        $this->app->register(AppServiceProvider::class);

        // Dispatch the CommandStarting event
        $this->app['events']->dispatch(new \Illuminate\Console\Events\CommandStarting(
            'test:command',
            new \Symfony\Component\Console\Input\ArrayInput([]),
            new \Symfony\Component\Console\Output\NullOutput()
        ));

        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_if_not_production()
    {
        Config::set('ids.agent_token', '');
        $this->app['env'] = 'local';

        $this->app->register(AppServiceProvider::class);

        // Dispatch the CommandStarting event
        $this->app['events']->dispatch(new \Illuminate\Console\Events\CommandStarting(
            'test:command',
            new \Symfony\Component\Console\Input\ArrayInput([]),
            new \Symfony\Component\Console\Output\NullOutput()
        ));

        $this->assertTrue(true); // Reached without exception
    }
}
