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
        // unblockIP returns true if an IP was actually unblocked.
        // If it returns false, it usually means the IP was already unblocked (idempotent),
        // so we don't want to throw an exception and cause unnecessary retries.
        if (!$blockingService->unblockIP($this->ip)) {
            Log::info('UnblockIPJob: IP was not blocked or already unblocked', ['ip' => $this->ip]);
        }
    }
}
