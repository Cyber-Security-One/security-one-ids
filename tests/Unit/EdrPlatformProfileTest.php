<?php

namespace Tests\Unit;

use App\Services\Correlation\EdrFacetExtractor;
use App\Services\Correlation\EdrLineageResolver;
use App\Services\Platform\EdrPlatformProfile;
use Tests\TestCase;

/**
 * The platform vocabulary, on both platforms.
 *
 * These tests run on Linux and exercise the Darwin profile by construction —
 * which verifies that the *logic* handles the macOS vocabulary, and nothing
 * more. No Mac has been watched from here, and the difference matters: the
 * assertions below would all pass on a build where EndpointSecurity never
 * attaches. What they do rule out is the failure mode that has no symptom —
 * a compiled-in Linux fact silently applied to a Mac, where `/usr/bin` is
 * still a system directory but every Homebrew binary lands in "other" and
 * `systemd` anchors nothing at all.
 */
class EdrPlatformProfileTest extends TestCase
{
    protected function tearDown(): void
    {
        // The extractor holds the vocabulary in static state, so a test that
        // switches platform must put it back or it leaks into the next one.
        EdrFacetExtractor::usePlatform(EdrPlatformProfile::current());

        parent::tearDown();
    }

    /**
     * The directory classes are what the novelty model keys on, so a stale
     * list does not fail — it collapses a dimension.
     */
    public function test_directory_classes_follow_the_platform(): void
    {
        EdrFacetExtractor::usePlatform(EdrPlatformProfile::for(EdrPlatformProfile::DARWIN));

        $this->assertSame('sys', EdrFacetExtractor::dirclass('/usr/bin/curl'));
        $this->assertSame('sys', EdrFacetExtractor::dirclass('/System/Library/CoreServices/launchd'));
        $this->assertSame('pkg', EdrFacetExtractor::dirclass('/opt/homebrew/bin/curl'));
        $this->assertSame('pkg', EdrFacetExtractor::dirclass('/Applications/Xcode.app/Contents/MacOS/Xcode'));
        $this->assertSame('home', EdrFacetExtractor::dirclass('/Users/deploy/bin/tool'));
        $this->assertSame('tmp', EdrFacetExtractor::dirclass('/private/tmp/.payload'));
        $this->assertSame('tmp', EdrFacetExtractor::dirclass('/var/folders/xy/T/.stage'));

        EdrFacetExtractor::usePlatform(EdrPlatformProfile::for(EdrPlatformProfile::LINUX));

        $this->assertSame('sys', EdrFacetExtractor::dirclass('/usr/bin/curl'));
        $this->assertSame('home', EdrFacetExtractor::dirclass('/home/deploy/bin/tool'));
        $this->assertSame('tmp', EdrFacetExtractor::dirclass('/dev/shm/.payload'));

        // The two vocabularies genuinely differ rather than one being a
        // superset. /opt is a package directory on both, but an .app bundle
        // means nothing on Linux and /Users is not a home directory there.
        $this->assertSame('other', EdrFacetExtractor::dirclass('/Applications/Xcode.app/Contents/MacOS/Xcode'));
        $this->assertSame('other', EdrFacetExtractor::dirclass('/Users/deploy/bin/tool'));
    }

    /**
     * `launchd` is macOS's service manager, session manager and scheduler at
     * once. Without it in the anchor list every chain on a Mac would anchor as
     * an orphan and fall into a five-minute time bucket — the actor key would
     * change every five minutes and the property the whole correlator exists
     * for would be gone, silently.
     */
    public function test_anchor_vocabulary_follows_the_platform(): void
    {
        $darwin = EdrPlatformProfile::for(EdrPlatformProfile::DARWIN);
        $linux = EdrPlatformProfile::for(EdrPlatformProfile::LINUX);

        $this->assertContains('launchd', $darwin->anchorImages());
        $this->assertNotContains('systemd', $darwin->anchorImages());
        $this->assertContains('systemd', $linux->anchorImages());
        $this->assertNotContains('launchd', $linux->anchorImages());

        $this->assertSame(['launchd'], $darwin->anchorKinds()['init']);
        $this->assertContains('loginwindow', $darwin->anchorKinds()['desktop']);

        // Containers are not observable from a macOS host, so claiming an
        // anchor kind for them would describe a chain that cannot occur.
        $this->assertSame([], $darwin->anchorKinds()['container']);
    }

    /**
     * A chain has to pass through a wrapper, and the wrappers differ.
     */
    public function test_transparent_wrappers_follow_the_platform(): void
    {
        $this->assertContains(
            'setsid',
            EdrPlatformProfile::for(EdrPlatformProfile::LINUX)->transparentWrappers()
        );
        $this->assertContains(
            'caffeinate',
            EdrPlatformProfile::for(EdrPlatformProfile::DARWIN)->transparentWrappers()
        );
    }

    /**
     * The package-manager discount must name the right managers, or an
     * upgrade on the wrong platform is charged at full price and a legitimate
     * `brew upgrade` becomes an incident.
     */
    public function test_package_managers_follow_the_platform(): void
    {
        $darwin = EdrPlatformProfile::for(EdrPlatformProfile::DARWIN)->packageManagers();

        $this->assertContains('brew', $darwin);
        $this->assertContains('softwareupdate', $darwin);
        $this->assertNotContains('apt-get', $darwin);
    }

    /**
     * `_www` is Apache's account on macOS. Missing it removes the webshell
     * detection — the single highest-value host signal in the product — with
     * no rule appearing to fail.
     */
    public function test_macos_web_accounts_are_recognised(): void
    {
        $this->assertContains('_www', EdrPlatformProfile::for(EdrPlatformProfile::DARWIN)->webAccounts());
        $this->assertContains('www-data', EdrPlatformProfile::for(EdrPlatformProfile::LINUX)->webAccounts());
    }

    /**
     * Two things macOS genuinely cannot answer, stated as values rather than
     * as branches that never execute.
     *
     * A rule conditioned on "inside a container" does not fail on a Mac — it
     * never fires, while still counting as coverage. And an event clock that
     * cannot be anchored must degrade to the flush time rather than produce a
     * confident wrong timestamp.
     */
    public function test_the_platform_states_what_it_cannot_observe(): void
    {
        $darwin = EdrPlatformProfile::for(EdrPlatformProfile::DARWIN);
        $linux = EdrPlatformProfile::for(EdrPlatformProfile::LINUX);

        $this->assertSame('not_observable', $darwin->containerVisibility());
        $this->assertSame('observable', $linux->containerVisibility());

        $this->assertFalse($darwin->canAnchorEventClock());
        $this->assertTrue($linux->canAnchorEventClock());

        // No socket event table on macOS. Reported as absent so the scheduler
        // omits the query rather than asking for a table that is not there.
        $this->assertNull($darwin->sensorTables()['socket']);
        $this->assertSame('endpointsecurity', $darwin->sensorTables()['backend']);
        $this->assertSame('bpf_socket_events', $linux->sensorTables('bpf')['socket']);
    }

    /**
     * Container path collapsing exists to stop every image layer minting a
     * fresh vocabulary. On macOS there are no such paths to collapse, and
     * inventing a mapping for them would be describing something that cannot
     * happen.
     */
    public function test_container_path_collapsing_is_linux_only(): void
    {
        EdrFacetExtractor::usePlatform(EdrPlatformProfile::for(EdrPlatformProfile::LINUX));

        $overlay = '/var/lib/docker/overlay2/abcdef0123456789/diff/usr/bin/curl';
        $this->assertStringStartsWith('/‹ovl›', EdrFacetExtractor::normalisePath($overlay));

        EdrFacetExtractor::usePlatform(EdrPlatformProfile::for(EdrPlatformProfile::DARWIN));
        $this->assertSame($overlay, EdrFacetExtractor::normalisePath($overlay));
    }

    /**
     * The resolver takes its vocabulary from the profile it is given, so a
     * macOS chain anchors on launchd instead of falling through to orphan.
     */
    public function test_the_resolver_accepts_a_platform_profile(): void
    {
        $path = sys_get_temp_dir() . '/edr-plat-' . uniqid() . '.sqlite';

        $store = new \App\Services\Correlation\EdrCorrelatorStore($path);
        $resolver = new EdrLineageResolver($store, null, [
            'platform' => EdrPlatformProfile::for(EdrPlatformProfile::DARWIN),
        ]);

        $this->assertSame('init', $resolver->classifyAnchor('sys:launchd'));
        $this->assertSame('web', $resolver->classifyAnchor('pkg:nginx'));
        $this->assertSame('desktop', $resolver->classifyAnchor('sys:loginwindow'));
        $this->assertSame('unknown', $resolver->classifyAnchor('sys:systemd'));

        $store->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($path . $suffix);
        }
    }
}
