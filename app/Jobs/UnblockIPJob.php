<?php

namespace App\Jobs;

use App\Services\BlockingService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

/**
 * Unblock IP Job
 *
 * Async job to unblock an IP address after its block duration expires
 */
class UnblockIPJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 3;

    /**
     * Create a new job instance.
     */
    public function __construct(
        public readonly string $ip
    ) {
        // Use IDS queue configurations to prevent env mismatch
        $this->onConnection(config('ids.queue.connection', 'database'));
        $this->onQueue(config('ids.queue.name', 'ids-processing'));
    }

    /**
     * Execute the job.
     */
    public function handle(BlockingService $blockingService): void
    {
        Log::info('Executing UnblockIPJob', ['ip' => $this->ip]);

        $unblocked = $blockingService->unblockIP($this->ip);
        if (!$unblocked) {
            Log::warning('UnblockIPJob unblock failed, will retry', ['ip' => $this->ip]);
            throw new \RuntimeException("Failed to unblock IP: {$this->ip}");
        }
    }
}
