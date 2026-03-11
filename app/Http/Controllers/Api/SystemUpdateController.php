<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Log;

class SystemUpdateController extends Controller
{
    /**
     * Trigger system update (git pull + rebuild)
     */
    public function update(Request $request)
    {
        Log::info('System update triggered via API');

        // Run update command in background
        $command = 'cd /var/www/html && git pull origin main 2>&1';
        
        try {
            exec($command, $output, $returnCode);
            
            if ($returnCode === 0) {
                // Clear caches
                Artisan::call('config:clear');
                Artisan::call('cache:clear');
                
                Log::info('System update completed', [
                    'output' => implode("\n", $output),
                ]);

                return response()->json([
                    'success' => true,
                    'message' => '更新成功',
                    'output' => $output,
                ]);
            }

            Log::error('System update failed', [
                'return_code' => $returnCode,
                'output' => $output,
            ]);

            return response()->json([
                'success' => false,
                'message' => '更新失敗',
                'output' => $output,
            ], 500);

        } catch (\Exception $e) {
            Log::error('System update exception', [
                'error' => $e->getMessage(),
            ]);

            return response()->json([
                'success' => false,
                'message' => '更新錯誤: ' . $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Get current version info
     */
    public function version()
    {
        $version = '1.0.0';
        $gitHash = '';
        $gitBranch = '';

        try {
            // Get git info
            exec('git rev-parse HEAD 2>/dev/null', $hashOutput);
            exec('git rev-parse --abbrev-ref HEAD 2>/dev/null', $branchOutput);
            
            $gitHash = !empty($hashOutput) ? substr($hashOutput[0], 0, 7) : 'unknown';
            $gitBranch = !empty($branchOutput) ? $branchOutput[0] : 'unknown';
        } catch (\Exception $e) {
            // Ignore git errors
        }

        return response()->json([
            'version' => $version,
            'git_hash' => $gitHash,
            'git_branch' => $gitBranch,
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
        ]);
    }

    /**
     * Restart services
     */
    public function restart()
    {
        Log::info('Service restart triggered');

        try {
            exec('supervisorctl restart all 2>&1', $output, $returnCode);

            return response()->json([
                'success' => $returnCode === 0,
                'message' => $returnCode === 0 ? '服務已重啟' : '重啟失敗',
                'output' => $output,
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => '重啟錯誤: ' . $e->getMessage(),
            ], 500);
        }
    }
}
