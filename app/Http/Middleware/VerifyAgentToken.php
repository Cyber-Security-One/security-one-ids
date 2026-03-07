<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class VerifyAgentToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->input('token') ?? $request->header('X-Agent-Token') ?? $request->bearerToken();
        $agentToken = config('ids.agent_token', env('AGENT_TOKEN'));

        if (empty($agentToken)) {
            return response()->json(['error' => 'Agent token not configured'], 500);
        }

        if (empty($token) || !hash_equals((string)$agentToken, (string)$token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
