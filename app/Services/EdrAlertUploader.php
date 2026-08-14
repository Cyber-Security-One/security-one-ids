<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

/**
 * Drains queued EDR alerts from the spool to the Hub.
 *
 * Delivery deliberately runs off the spool rather than off the collection
 * cycle. In the previous design an alert existed only in memory for the
 * length of one sync: if the Hub was down, restarting, or rejecting, the
 * finding was gone. Now the collector's only job is to get events onto disk,
 * and this class is the sole thing that talks to the Hub — so an outage
 * becomes a delay instead of data loss.
 *
 * Rows are marked sent only after the Hub has acknowledged. Duplicate
 * delivery after a crash between "Hub accepted" and "we recorded it" is the
 * correct failure mode: a duplicate alert is an annoyance, a missing alert is
 * an incident nobody sees.
 */
class EdrAlertUploader
{
    /** Alerts per HTTP request. */
    private const DEFAULT_BATCH_SIZE = 200;

    /** Requests per flush, so one cycle cannot run unbounded. */
    private const MAX_BATCHES_PER_CYCLE = 5;

    /** Below this, compression costs more CPU than it saves bytes. */
    private const MIN_COMPRESS_BYTES = 2048;

    private const BACKOFF_CACHE_KEY = 'edr_upload_backoff_until';
    private const COMPRESSION_DISABLED_KEY = 'edr_upload_compression_disabled_until';

    private EdrEventSpool $spool;
    private EdrAlertFactory $factory;
    private WafSyncService $sync;

    public function __construct(EdrEventSpool $spool, EdrAlertFactory $factory, WafSyncService $sync)
    {
        $this->spool = $spool;
        $this->factory = $factory;
        $this->sync = $sync;
    }

    /**
     * Ship whatever is queued.
     *
     * @return array{sent:int, batches:int, failed:bool, skipped:string|null, remaining:int}
     */
    public function flush(array $options = []): array
    {
        $result = ['sent' => 0, 'batches' => 0, 'failed' => false, 'skipped' => null, 'remaining' => 0];

        $backoffUntil = (int) cache()->get(self::BACKOFF_CACHE_KEY, 0);
        if ($backoffUntil > time()) {
            $result['skipped'] = 'backoff';
            $result['remaining'] = $this->spool->stats()['pending'];

            return $result;
        }

        $batchSize = max(1, min(1000, (int) ($options['upload_batch_size'] ?? self::DEFAULT_BATCH_SIZE)));
        $compress = (bool) ($options['upload_compression'] ?? false);

        for ($batch = 0; $batch < self::MAX_BATCHES_PER_CYCLE; $batch++) {
            $rows = $this->spool->pending($batchSize);
            if ($rows === []) {
                break;
            }

            $alerts = [];
            $ids = [];
            $unusable = [];

            foreach ($rows as $row) {
                $alert = $this->factory->fromSpoolRow($row);

                if ($alert === null) {
                    // Cannot be rendered into an alert — retiring it keeps a
                    // single bad row from blocking the queue forever.
                    $unusable[] = (int) $row['id'];
                    continue;
                }

                $alerts[] = $alert;
                $ids[] = (int) $row['id'];
            }

            if ($unusable !== []) {
                Log::warning('[EDR upload] Retiring unrenderable spool rows', ['count' => count($unusable)]);
                $this->spool->markSent($unusable);
            }

            if ($alerts === []) {
                continue;
            }

            $outcome = $this->send($alerts, $compress);

            if (!$outcome['ok']) {
                $this->applyBackoff($outcome);
                $result['failed'] = true;
                break;
            }

            $this->spool->markSent($ids);
            $result['sent'] += count($alerts);
            $result['batches']++;
        }

        if (!$result['failed']) {
            cache()->forget(self::BACKOFF_CACHE_KEY);
            $this->resetFailureCounter();
        }

        $result['remaining'] = $this->spool->stats()['pending'];

        if ($result['sent'] > 0) {
            Log::info('[EDR upload] Delivered alerts to Hub', [
                'sent' => $result['sent'],
                'batches' => $result['batches'],
                'remaining' => $result['remaining'],
            ]);
        }

        return $result;
    }

    /**
     * @return array{ok:bool, status:int|null, retry_after:int|null, reason:string|null}
     */
    private function send(array $alerts, bool $compress): array
    {
        $config = $this->sync->getConnectionConfig();

        if ($config['url'] === '' || $config['token'] === '') {
            return ['ok' => false, 'status' => null, 'retry_after' => null, 'reason' => 'not_configured'];
        }

        $payload = [
            'token' => $config['token'],
            'alerts' => $alerts,
        ];

        try {
            // Authenticate in the header as well as the body. The body copy is
            // the existing Hub contract, but a gzipped body cannot be read
            // until it is decompressed — so a Hub that authenticates before
            // decompressing sees only compressed bytes where the token should
            // be and rejects every compressed upload. The header is readable
            // either way, which makes the compressed path independent of that
            // ordering.
            $request = $this->sync->httpClient(60)
                ->withHeaders(['Authorization' => 'Bearer ' . $config['token']]);

            // Compression is negotiated, not assumed: PHP does not decode a
            // gzipped request body on its own and nginx will not do it for
            // us, so sending it blind to a Hub that cannot read it would turn
            // every upload into a 400. Off unless the Hub says it can.
            if ($compress && !$this->compressionSuspended()) {
                $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

                if ($json !== false && strlen($json) >= self::MIN_COMPRESS_BYTES) {
                    $gzipped = gzencode($json, 6);

                    if ($gzipped !== false) {
                        $response = $request
                            ->withHeaders([
                                'Content-Type' => 'application/json',
                                'Content-Encoding' => 'gzip',
                            ])
                            ->withBody($gzipped, 'application/json')
                            ->post("{$config['url']}/api/ids/agents/alerts");

                        if ($response->successful()) {
                            return ['ok' => true, 'status' => $response->status(), 'retry_after' => null, 'reason' => null];
                        }

                        // A Hub that cannot decode gzip fails the same way
                        // every time; stop paying for it for a while and fall
                        // back to plain JSON rather than stalling the queue.
                        if (in_array($response->status(), [400, 411, 415, 422], true)) {
                            Log::warning('[EDR upload] Hub rejected compressed body, falling back to plain', [
                                'status' => $response->status(),
                            ]);
                            cache()->put(self::COMPRESSION_DISABLED_KEY, time() + 3600, now()->addDay());
                        } else {
                            return $this->failureFrom($response);
                        }
                    }
                }
            }

            $response = $request->post("{$config['url']}/api/ids/agents/alerts", $payload);

            if ($response->successful()) {
                return ['ok' => true, 'status' => $response->status(), 'retry_after' => null, 'reason' => null];
            }

            return $this->failureFrom($response);
        } catch (\Exception $e) {
            Log::warning('[EDR upload] Transport error: ' . $e->getMessage());

            return ['ok' => false, 'status' => null, 'retry_after' => null, 'reason' => 'transport'];
        }
    }

    private function failureFrom(\Illuminate\Http\Client\Response $response): array
    {
        $retryAfter = (int) $response->header('Retry-After');

        Log::warning('[EDR upload] Hub rejected batch', [
            'status' => $response->status(),
            'body' => substr($response->body(), 0, 300),
        ]);

        return [
            'ok' => false,
            'status' => $response->status(),
            'retry_after' => $retryAfter > 0 ? $retryAfter : null,
            'reason' => 'http_' . $response->status(),
        ];
    }

    /**
     * Exponential backoff, capped. The point is to stop hammering a Hub that
     * is already struggling — a fleet of agents retrying every 30 seconds is
     * how a brief outage becomes a long one.
     */
    private function applyBackoff(array $outcome): void
    {
        if ($outcome['retry_after'] !== null) {
            $delay = min(3600, max(30, $outcome['retry_after']));
        } else {
            $failures = (int) cache()->get('edr_upload_failures', 0) + 1;
            cache()->put('edr_upload_failures', $failures, now()->addDay());
            $delay = min(1800, 30 * (2 ** min(6, $failures - 1)));
        }

        cache()->put(self::BACKOFF_CACHE_KEY, time() + $delay, now()->addDay());

        Log::info('[EDR upload] Backing off', [
            'seconds' => $delay,
            'reason' => $outcome['reason'],
        ]);
    }

    private function compressionSuspended(): bool
    {
        return (int) cache()->get(self::COMPRESSION_DISABLED_KEY, 0) > time();
    }

    /**
     * Cleared on a successful flush so a recovered Hub is not held back by an
     * old failure streak.
     */
    public function resetFailureCounter(): void
    {
        cache()->forget('edr_upload_failures');
    }
}
