<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

class SystemUpdateController extends Controller
{
    /**
     * Trigger system update (git pull + rebuild)
     */
    public function update(Request $request)
    {
        Log::info('System update triggered via API');

        try {
            $result = Process::path(base_path())->run(['git', 'pull', 'origin', 'main']);
            $returnCode = $result->exitCode();
            $output = explode("\n", trim($result->output() . "\n" . $result->errorOutput()));
            
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
            $hashResult = Process::path(base_path())->run(['git', 'rev-parse', 'HEAD']);
            $branchResult = Process::path(base_path())->run(['git', 'rev-parse', '--abbrev-ref', 'HEAD']);

            $hashOutput = array_filter(explode("\n", trim($hashResult->output())));
            $branchOutput = array_filter(explode("\n", trim($branchResult->output())));
            
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
            $result = Process::run(['supervisorctl', 'restart', 'all']);
            $returnCode = $result->exitCode();
            $output = explode("\n", trim($result->output() . "\n" . $result->errorOutput()));

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
