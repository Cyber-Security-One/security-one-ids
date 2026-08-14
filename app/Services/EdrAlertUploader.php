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

                // The spool row id travels with the alert so the Hub can say
                // which ones it kept. Without a per-alert handle the only
                // possible answer is "the batch succeeded", and a batch where
                // 199 stored and one failed is then indistinguishable from a
                // clean 200 — the failed one is marked delivered and deleted.
                $alert['client_id'] = (string) $row['id'];

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

            // Too large. Backing off and retrying is the one response that
            // cannot work: the next cycle fetches exactly the same rows and
            // gets exactly the same answer, so the queue stops forever and
            // nothing says so. Halve and retry instead; a single alert that
            // still will not fit is retired loudly, because one unshippable
            // row must not block every alert behind it.
            if (!$outcome['ok'] && $outcome['status'] === 413) {
                if ($batchSize > 1) {
                    $batchSize = max(1, intdiv($batchSize, 2));

                    Log::warning('[EDR upload] Hub rejected batch as too large, halving', [
                        'new_batch_size' => $batchSize,
                        'alerts' => count($alerts),
                    ]);

                    continue;
                }

                Log::error('[EDR upload] Retiring a single alert the Hub cannot accept', [
                    'id' => $ids[0] ?? null,
                    'bytes' => strlen((string) json_encode($alerts[0] ?? [])),
                ]);

                $this->spool->markSent($ids);

                continue;
            }

            if (!$outcome['ok']) {
                $this->applyBackoff($outcome);
                $result['failed'] = true;
                break;
            }

            // Per-alert acknowledgement when the Hub offers it, whole-batch
            // when it does not.
            //
            // A batch where 199 stored and one failed used to be acknowledged
            // as a whole, so the failed one was marked delivered and deleted.
            // Only what the Hub says it accepted is retired here; anything it
            // neither accepted nor rejected stays queued for the next attempt.
            $settled = $ids;

            if (is_array($outcome['accepted'] ?? null)) {
                // Matched as strings. `client_id` is sent as a string and the
                // Hub echoes back whatever it was given, so comparing on a
                // numeric interpretation would couple this to an id format
                // neither side has promised to keep.
                $mine = array_map('strval', $ids);
                $accepted = array_map('intval', array_intersect($mine, $outcome['accepted']));
                $rejected = array_map('intval', array_intersect($mine, $outcome['rejected'] ?? []));

                // Rejected is not the same as failed. The Hub has told us it
                // will never take these, so holding them would block every
                // alert behind them forever — the queue-stalling failure the
                // 413 path already had to solve. Retired loudly instead.
                if ($rejected !== []) {
                    Log::error('[EDR upload] Hub rejected alerts outright, retiring them', [
                        'count' => count($rejected),
                        'ids' => array_slice($rejected, 0, 20),
                    ]);
                }

                $held = count($ids) - count($accepted) - count($rejected);

                if ($held > 0) {
                    Log::warning('[EDR upload] Hub acknowledged only part of the batch, holding the rest', [
                        'sent' => count($ids),
                        'accepted' => count($accepted),
                        'rejected' => count($rejected),
                        'held' => $held,
                    ]);
                }

                $settled = array_merge($accepted, $rejected);
                $result['sent'] += count($accepted);
            } else {
                $result['sent'] += count($alerts);
            }

            if ($settled !== []) {
                $this->spool->markSent($settled);
            }

            $result['batches']++;

            // Nothing settled means the next page would return the same rows;
            // stop rather than spin.
            if ($settled === []) {
                break;
            }
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

        $endpoint = "{$config['url']}/api/ids/agents/alerts";

        // The body is built once, here, and both paths send these exact bytes.
        //
        // Letting the client library encode the array meant the bytes actually
        // transmitted were never inspectable from this class — which is how a
        // request with an empty body got sent and acknowledged. Owning the
        // string makes the check below possible at all, and the check does not
        // depend on how any framework chooses to behave.
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($json === false || $json === '' || !str_contains($json, '"alerts"')) {
            Log::error('[EDR upload] Refusing to send a batch that encoded to nothing', [
                'alerts' => count($alerts),
            ]);

            return ['ok' => false, 'status' => null, 'retry_after' => null, 'reason' => 'empty_body'];
        }

        try {
            // Compression is negotiated, not assumed: PHP does not decode a
            // gzipped request body on its own and nginx will not do it for
            // us, so sending it blind to a Hub that cannot read it would turn
            // every upload into a 400. Off unless the Hub says it can.
            if ($compress && !$this->compressionSuspended()) {
                if (strlen($json) >= self::MIN_COMPRESS_BYTES) {
                    $gzipped = gzencode($json, 6);

                    if ($gzipped !== false) {
                        $response = $this->request($config)
                            ->withHeaders([
                                'Content-Type' => 'application/json',
                                'Content-Encoding' => 'gzip',
                            ])
                            ->withBody($gzipped, 'application/json')
                            ->post($endpoint);

                        if ($response->successful()) {
                            return $this->acceptanceOf($response, count($alerts));
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

            // A FRESH request, carrying the bytes built above.
            //
            // Laravel's PendingRequest is mutable — withHeaders() and
            // withBody() both return $this — so reusing the object from the
            // compression attempt carried its `Content-Encoding: gzip` header
            // and its already-set body into the fallback. The result was a
            // request with a **zero-length body** still labelled gzip; a Hub
            // that answers an empty alert list with 2xx would then have the
            // whole batch marked delivered and every alert in it destroyed,
            // with nothing in the log but a successful upload. Reproduced
            // against the installed framework before this was changed.
            $response = $this->request($config)
                ->withBody($json, 'application/json')
                ->post($endpoint);

            if ($response->successful()) {
                return $this->acceptanceOf($response, count($alerts));
            }

            return $this->failureFrom($response);
        } catch (\Exception $e) {
            Log::warning('[EDR upload] Transport error: ' . $e->getMessage());

            return ['ok' => false, 'status' => null, 'retry_after' => null, 'reason' => 'transport'];
        }
    }

    /**
     * A clean request for one attempt, never shared between them.
     *
     * Authentication goes in the header as well as the body. The body copy is
     * the existing Hub contract, but a gzipped body cannot be read until it is
     * decompressed — so a Hub that authenticates before decompressing sees
     * only compressed bytes where the token should be and rejects every
     * compressed upload. The header is readable either way.
     */
    private function request(array $config): \Illuminate\Http\Client\PendingRequest
    {
        return $this->sync->httpClient(60)
            ->withHeaders(['Authorization' => 'Bearer ' . $config['token']]);
    }

    /**
     * Did the Hub actually keep what we sent?
     *
     * A 2xx alone is not proof. The Hub has been observed logging a storage
     * failure and answering 201 in the same second, and the agent read nothing
     * but the status — so a batch could be marked delivered and deleted while
     * the Hub held none of it.
     *
     * Deliberately narrow. `stored` being lower than what we sent is normal
     * and expected: the Hub deduplicates, and reporting that as a failure
     * would manufacture exactly the retry loop the deduplication exists to
     * absorb. The only case treated as failure is the unambiguous one — the
     * Hub says it stored nothing and skipped nothing, which cannot be a
     * duplicate and cannot be a success.
     */
    private function acceptanceOf(\Illuminate\Http\Client\Response $response, int $sent): array
    {
        $ok = [
            'ok' => true,
            'status' => $response->status(),
            'retry_after' => null,
            'reason' => null,
            'accepted' => null,
            'rejected' => null,
        ];

        if ($sent === 0) {
            return $ok;
        }

        $body = $response->json();

        // Per-alert acknowledgement, when the Hub speaks it. Absent, the whole
        // batch is settled together — which is what every existing Hub does
        // and must keep working.
        if (is_array($body) && isset($body['accepted']) && is_array($body['accepted'])) {
            $ok['accepted'] = array_map('strval', $body['accepted']);
            $ok['rejected'] = array_map(
                static fn ($entry): string => (string) (is_array($entry) ? ($entry['client_id'] ?? '') : $entry),
                is_array($body['rejected'] ?? null) ? $body['rejected'] : []
            );

            return $ok;
        }

        if (!is_array($body) || !array_key_exists('stored', $body)) {
            // An older Hub that does not report it. Nothing to check against.
            return $ok;
        }

        $stored = (int) $body['stored'];
        $skipped = (int) ($body['duplicates_skipped'] ?? 0);

        if ($stored > 0 || $skipped > 0) {
            return $ok;
        }

        Log::error('[EDR upload] Hub acknowledged but stored nothing, holding the batch', [
            'status' => $response->status(),
            'sent' => $sent,
            'stored' => $stored,
            'duplicates_skipped' => $skipped,
        ]);

        return [
            'ok' => false,
            'status' => $response->status(),
            'retry_after' => null,
            'reason' => 'stored_nothing',
        ];
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
