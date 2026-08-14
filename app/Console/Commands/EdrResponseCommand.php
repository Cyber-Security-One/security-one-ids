<?php

namespace App\Console\Commands;

use App\Services\Response\EdrActionLedger;
use App\Services\Response\EdrResponder;
use App\Services\Response\NetworkContainment;
use Illuminate\Console\Command;

/**
 * Field control for endpoint response.
 *
 * The command that matters here is `--release-network`. If a host is
 * contained and the Hub cannot reach it, somebody with console access needs a
 * way to lift it that does not depend on the thing that is broken.
 */
class EdrResponseCommand extends Command
{
    protected $signature = 'ids:edr-response
        {--status : Show what is currently in effect}
        {--list : List recent response actions}
        {--limit=20 : How many actions to list}
        {--expire : Run the rollback pass for anything past its deadline}
        {--report : Push unreported outcomes to the Hub}
        {--reconcile : Correct the record where it disagrees with reality}
        {--release-network : Lift network isolation locally, without the Hub}';

    protected $description = 'Inspect and control EDR response actions on this endpoint';

    public function handle(EdrResponder $responder, EdrActionLedger $ledger, NetworkContainment $network): int
    {
        if ($this->option('release-network')) {
            return $this->releaseNetwork($responder, $ledger, $network);
        }

        if ($this->option('expire')) {
            $result = $responder->expireOverdue();
            $this->info("Reverted {$result['reverted']} action(s), {$result['failed']} failed.");

            return $result['failed'] > 0 ? 1 : 0;
        }

        if ($this->option('reconcile')) {
            $result = $responder->reconcile();
            $this->info("Checked {$result['checked']}, corrected {$result['corrected']}.");

            return 0;
        }

        if ($this->option('report')) {
            $result = $responder->reportOutcomes();
            $this->info("Reported {$result['reported']}, {$result['remaining']} still queued.");

            return 0;
        }

        if ($this->option('list')) {
            return $this->listActions($ledger, (int) $this->option('limit'));
        }

        return $this->showStatus($responder, $network);
    }

    private function showStatus(EdrResponder $responder, NetworkContainment $network): int
    {
        $status = $responder->getStatus();

        $this->info('EDR Response Status');
        $this->line(str_repeat('=', 46));

        $isolated = $status['network']['active'];
        $this->line(sprintf('  %-22s %s', 'network_isolated', $isolated ? 'YES' : 'no'));
        $this->line(sprintf('  %-22s %s', 'iptables_supported', $status['network']['supported'] ? 'yes' : 'no'));
        $this->line(sprintf('  %-22s %d', 'quarantined_files', $status['quarantined']));

        $ledger = $status['ledger'];
        $this->line(sprintf('  %-22s %s', 'ledger_available', $ledger['available'] ? 'yes' : 'no'));
        $this->line(sprintf('  %-22s %d', 'actions_total', $ledger['total']));
        $this->line(sprintf('  %-22s %d', 'actions_applied', $ledger['applied']));
        $this->line(sprintf('  %-22s %d', 'actions_reverted', $ledger['reverted']));
        $this->line(sprintf('  %-22s %d', 'actions_failed', $ledger['failed']));
        $this->line(sprintf('  %-22s %d', 'awaiting_report', $ledger['unreported']));
        $this->line(sprintf('  %-22s %d', 'stuck_pending', $ledger['pending']));

        if ($isolated) {
            $this->newLine();
            $this->warn('  This host is network-isolated.');
            $this->line('  Lift it locally with: php artisan ids:edr-response --release-network');
        }

        if ($ledger['pending'] > 0) {
            $this->newLine();
            $this->warn('  Some actions are recorded but never resolved — the agent may have died mid-action.');
            $this->line('  Their side effects are unknown; review with --list before assuming either way.');
        }

        return 0;
    }

    private function listActions(EdrActionLedger $ledger, int $limit): int
    {
        $actions = $ledger->recent(max(1, $limit));

        if ($actions === []) {
            $this->line('No response actions recorded.');

            return 0;
        }

        foreach ($actions as $action) {
            $when = date('Y-m-d H:i:s', (int) $action['created_at']);
            $state = strtoupper((string) $action['state']);

            $this->line(sprintf('  [%s] %-9s %-18s %s', $when, $state, $action['type'], $action['action_id']));

            if (!empty($action['reason'])) {
                $this->line('      reason: ' . $action['reason']);
            }
            if (!empty($action['requested_by'])) {
                $this->line('      by:     ' . $action['requested_by']);
            }
            if (!empty($action['target'])) {
                $this->line('      target: ' . json_encode($action['target'], JSON_UNESCAPED_SLASHES));
            }
            if (!empty($action['error'])) {
                $this->line('      error:  ' . $action['error']);
            }
            if (!empty($action['expires_at'])) {
                $this->line('      expires: ' . date('Y-m-d H:i:s', (int) $action['expires_at']));
            }
        }

        return 0;
    }

    /**
     * The break-glass path. Deliberately available without the Hub, because
     * the situation this exists for is "the Hub cannot reach this host".
     */
    private function releaseNetwork(
        EdrResponder $responder,
        EdrActionLedger $ledger,
        NetworkContainment $network
    ): int {
        $state = $network->state();

        if ($state === false) {
            $this->line('Network isolation is not active on this host.');

            return 0;
        }

        if ($state === null) {
            // This is the break-glass path, so it does not stop here: not
            // knowing whether the host is isolated is a reason to attempt the
            // release, not a reason to skip it. Said out loud because the
            // operator needs to know the verification is unavailable.
            $this->warn('Cannot determine whether isolation is active (iptables unreadable — are you root?).');
            $this->warn('Attempting the release anyway; verify manually with: iptables -n -L SECONE_EDR_OUT');
        }

        $result = $network->release();

        if (empty($result['success'])) {
            $this->error('Failed to lift isolation: ' . ($result['error'] ?? 'unknown'));
            $this->line('Manual fallback:');
            $this->line('  iptables -D OUTPUT -j ' . NetworkContainment::CHAIN_OUT);
            $this->line('  iptables -D INPUT -j ' . NetworkContainment::CHAIN_IN);
            $this->line('  iptables -F ' . NetworkContainment::CHAIN_OUT . ' && iptables -X ' . NetworkContainment::CHAIN_OUT);
            $this->line('  iptables -F ' . NetworkContainment::CHAIN_IN . ' && iptables -X ' . NetworkContainment::CHAIN_IN);

            return 1;
        }

        // Close the ledger entries so the record matches what just happened.
        foreach ($ledger->applied('isolate_network') as $action) {
            $ledger->markReverted(
                $action['action_id'],
                EdrActionLedger::STATE_REVERTED,
                ['note' => 'released_locally_via_cli']
            );
        }

        $this->info('Network isolation lifted.');
        $this->line('The Hub will be told on the next sync.');

        return 0;
    }
}
