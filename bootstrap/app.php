<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
<<<<<<< HEAD
        api: __DIR__.'/../routes/api.php',
=======
>>>>>>> 44fde90 (Fix SymfonyProcess instantiation in WafSyncService)
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
<<<<<<< HEAD
        $middleware->alias([
            'agent_auth' => \App\Http\Middleware\AgentAuth::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
=======
        //
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
>>>>>>> 44fde90 (Fix SymfonyProcess instantiation in WafSyncService)
