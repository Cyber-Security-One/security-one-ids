<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class VerifyAgentToken
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->input('token') ?? $request->header('X-Agent-Token') ?? $request->bearerToken();
        $agentToken = (string) config('ids.agent_token', env('AGENT_TOKEN'));

        if ($agentToken === '') {
            return response()->json(['error' => 'Agent token not configured'], 500);
        }

        // Use hash_equals for all comparisons to prevent timing attacks.
        // We cast $token to string to ensure hash_equals doesn't fail on null.
        if (!hash_equals($agentToken, (string)$token)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
