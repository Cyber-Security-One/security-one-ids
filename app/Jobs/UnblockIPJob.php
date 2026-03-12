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
        // Run on the ids-processing queue as per memory guidelines
        $this->onQueue('ids-processing');
    }

    /**
     * Execute the job.
     */
    public function handle(BlockingService $blockingService): void
    {
        Log::info('Executing UnblockIPJob', ['ip' => $this->ip]);

        if (!$blockingService->isBlocked($this->ip)) {
            Log::info('UnblockIPJob skipped because IP is already unblocked', ['ip' => $this->ip]);
            return;
        }

        if (!$blockingService->unblockIP($this->ip)) {
            Log::error('UnblockIPJob failed to unblock IP', ['ip' => $this->ip]);
            throw new \RuntimeException("Failed to unblock IP: {$this->ip}");
        }
    }
}
