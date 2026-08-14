<?php

namespace App\Services\Identity;

/**
 * Recent authentication history, as the identity rules need to see it.
 *
 * An interface rather than a concrete lookup because the window rules are the
 * part of identity detection most worth testing exhaustively — brute force,
 * spraying and success-after-failure are all thresholds, and thresholds are
 * where off-by-one mistakes hide. Tests supply history directly instead of
 * having to stage a database and a clock.
 */
interface IdentityHistory
{
    /**
     * Failed authentications originating from an address.
     *
     * @return array<int, array> each with at least `username` and `ts`
     */
    public function failuresFrom(string $sourceIp, int $since, int $until): array;

    /**
     * Failed privilege escalations attempted by an account.
     *
     * @return array<int, array>
     */
    public function privilegeFailuresBy(string $actor, int $since, int $until): array;

    /**
     * Source addresses an account successfully authenticated from.
     *
     * @return array<int, string>
     */
    public function sourcesFor(string $username, int $since, int $until): array;

    /**
     * Addresses this account has successfully authenticated from before the
     * moment in question.
     *
     * This is what separates a person from an intruder in the case that
     * matters most. Nine failures then a success is the shape of a cracked
     * password — and also the shape of someone mistyping their own from the
     * laptop they use every day.
     *
     * Returning the whole set rather than a yes/no is deliberate: an empty
     * set means we have no basis for the judgement at all, which is a
     * different answer from "this address is new". A freshly deployed agent
     * knows nothing about anybody, and a rule that treats absence of history
     * as evidence of intrusion raises a critical alert for every normal login
     * in its first week.
     *
     * @return array<int, string>
     */
    public function knownSourcesFor(string $username, int $before): array;
}
