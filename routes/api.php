<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\SystemUpdateController;

// System Update API (for WAF Hub to trigger updates)
Route::prefix('api')->middleware(function ($request, $next) {
    $token = $request->input('token') ?? $request->header('X-Agent-Token') ?? $request->bearerToken();
    $agentToken = env('AGENT_TOKEN');

    if (empty($agentToken)) {
        return response()->json(['error' => 'Server Configuration Error: AGENT_TOKEN is not set.'], 500);
    }

    if (empty($token) || !hash_equals((string) $agentToken, (string) $token)) {
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    return $next($request);
})->group(function () {
    Route::post('/system/update', [SystemUpdateController::class, 'update']);
    Route::get('/system/version', [SystemUpdateController::class, 'version']);
    Route::post('/system/restart', [SystemUpdateController::class, 'restart']);
    
    // Rules update
    Route::post('/rules/update', function (\Illuminate\Http\Request $request) {
        $globalRules = $request->input('global_rules', []);
        $agentRules = $request->input('agent_rules', []);
        
        // Save rules to local storage
        $rulesPath = storage_path('app/ids_rules.json');
        file_put_contents($rulesPath, json_encode([
            'global_rules' => $globalRules,
            'agent_rules' => $agentRules,
            'updated_at' => now()->toIso8601String(),
        ], JSON_PRETTY_PRINT));
        
        \Illuminate\Support\Facades\Log::info('Rules updated via API', [
            'global_count' => count($globalRules),
            'agent_count' => count($agentRules),
        ]);
        
        return response()->json(['success' => true, 'message' => 'Rules updated']);
    });

    // Settings sync from WAF Hub
    Route::post('/settings/sync', function (\Illuminate\Http\Request $request) {
        $settings = $request->input('settings', []);
        
        // Store settings in environment cache/file
        $settingsPath = storage_path('app/ids_settings.json');
        $currentSettings = [];
        
        if (file_exists($settingsPath)) {
            $currentSettings = json_decode(file_get_contents($settingsPath), true) ?: [];
        }
        
        $newSettings = array_merge($currentSettings, $settings, [
            'updated_at' => now()->toIso8601String(),
        ]);
        
        file_put_contents($settingsPath, json_encode($newSettings, JSON_PRETTY_PRINT));
        
        \Illuminate\Support\Facades\Log::info('Settings synced from WAF Hub', $newSettings);
        
        // Also update runtime environment if possible
        if (isset($settings['ai_detection_enabled'])) {
            putenv('AI_DETECTION_ENABLED=' . ($settings['ai_detection_enabled'] ? 'true' : 'false'));
        }
        
        return response()->json([
            'success' => true,
            'message' => 'Settings synced',
            'settings' => $newSettings,
        ]);
    });
});
