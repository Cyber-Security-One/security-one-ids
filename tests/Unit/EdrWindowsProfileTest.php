<?php

namespace Tests\Unit;

use App\Services\Correlation\EdrFacetExtractor;
use App\Services\Platform\EdrPlatformProfile;
use PHPUnit\Framework\TestCase;

/**
 * The Windows vocabulary, and the two places it silently disappears.
 *
 * Nothing here has run on Windows. What these tests can establish is that the
 * code handles the Windows vocabulary — which is a different claim from "the
 * agent works on Windows", and the distinction is the whole reason the profile
 * is injectable.
 *
 * They concentrate on the failures that produce no error: a path that matches
 * no prefix and collapses a facet dimension, a clock that is present and
 * wrong, an account list that cannot name the accounts that exist. Every one
 * of those leaves an agent reporting that it is running while it detects
 * nothing.
 */
class EdrWindowsProfileTest extends TestCase
{
    private EdrPlatformProfile $windows;

    protected function setUp(): void
    {
        parent::setUp();
        $this->windows = EdrPlatformProfile::for(EdrPlatformProfile::WINDOWS);
    }

    protected function tearDown(): void
    {
        // The extractor holds the profile statically, so a test that leaves
        // Windows loaded would silently reclassify every path in whatever
        // runs next.
        EdrFacetExtractor::usePlatform(EdrPlatformProfile::for(EdrPlatformProfile::LINUX));
        parent::tearDown();
    }

    public function test_the_family_is_recognised_and_distinct(): void
    {
        $this->assertTrue($this->windows->isWindows());
        $this->assertFalse($this->windows->isDarwin());
        $this->assertSame('windows', $this->windows->family());

        $this->assertFalse(EdrPlatformProfile::for(EdrPlatformProfile::LINUX)->isWindows());
        $this->assertFalse(EdrPlatformProfile::for(EdrPlatformProfile::DARWIN)->isWindows());
    }

    /**
     * An unknown family must fall back to Linux rather than producing a
     * profile with no vocabulary at all. Empty lists do not throw; they just
     * classify everything as nothing.
     */
    public function test_an_unknown_family_falls_back_rather_than_emptying(): void
    {
        $profile = EdrPlatformProfile::for('plan9');

        $this->assertSame(EdrPlatformProfile::LINUX, $profile->family());
        $this->assertNotEmpty($profile->directoryClasses());
    }

    /* ------------------------------------------------------------------ */
    /* The clock                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Three platforms, three genuinely different clocks. This was a boolean,
     * and a boolean can hold two of them.
     */
    public function test_each_platform_reports_its_own_kind_of_clock(): void
    {
        $this->assertSame(EdrPlatformProfile::CLOCK_WALL, $this->windows->eventClock());
        $this->assertSame(
            EdrPlatformProfile::CLOCK_UNAVAILABLE,
            EdrPlatformProfile::for(EdrPlatformProfile::DARWIN)->eventClock()
        );
        $this->assertSame(
            EdrPlatformProfile::CLOCK_BOOT_RELATIVE,
            EdrPlatformProfile::for(EdrPlatformProfile::LINUX)->eventClock()
        );
    }

    /**
     * Windows must not be anchorable — its timestamps are already wall clock,
     * and adding a boot time to one would put every event in the future by
     * the machine's uptime.
     */
    public function test_only_the_boot_relative_platform_anchors(): void
    {
        $this->assertFalse($this->windows->canAnchorEventClock());
        $this->assertFalse(EdrPlatformProfile::for(EdrPlatformProfile::DARWIN)->canAnchorEventClock());
        $this->assertTrue(EdrPlatformProfile::for(EdrPlatformProfile::LINUX)->canAnchorEventClock());
    }

    /* ------------------------------------------------------------------ */
    /* Paths                                                               */
    /* ------------------------------------------------------------------ */

    public function test_windows_paths_are_folded_and_others_are_left_alone(): void
    {
        $this->assertSame(
            'c:/windows/system32/cmd.exe',
            $this->windows->foldPath('C:\\Windows\\System32\\cmd.exe')
        );

        $linux = EdrPlatformProfile::for(EdrPlatformProfile::LINUX);
        $this->assertSame('/usr/bin/CURL', $linux->foldPath('/usr/bin/CURL'), 'Linux paths are case-sensitive');
    }

    /**
     * The failure this whole exercise exists to prevent.
     *
     * Feed the extractor an unfolded Windows path and no prefix matches — not
     * one, ever. Every executable on the host lands in `other`, the image
     * facet collapses to a single value, and the novelty model loses a
     * dimension while reporting that it is running.
     */
    public function test_windows_paths_reach_a_real_directory_class(): void
    {
        EdrFacetExtractor::usePlatform($this->windows);

        $this->assertSame('sys', EdrFacetExtractor::dirclass('C:\\Windows\\System32\\cmd.exe'));
        $this->assertSame('pkg', EdrFacetExtractor::dirclass('C:\\Program Files\\Thing\\app.exe'));
        $this->assertSame('home', EdrFacetExtractor::dirclass('C:\\Users\\vito\\Downloads\\x.exe'));
        $this->assertSame('etc', EdrFacetExtractor::dirclass('C:\\inetpub\\wwwroot\\shell.aspx'));
    }

    public function test_casing_does_not_split_one_directory_into_two_facets(): void
    {
        EdrFacetExtractor::usePlatform($this->windows);

        $this->assertSame(
            EdrFacetExtractor::dirclass('C:\\Windows\\System32\\cmd.exe'),
            EdrFacetExtractor::dirclass('c:\\WINDOWS\\system32\\CMD.EXE')
        );
    }

    /**
     * The classes overlap, and first-match got the overlap backwards.
     *
     * `c:/windows/temp/` sits inside `c:/windows/`, so an ordered scan called
     * a dropper's favourite directory the system directory — saying the
     * opposite of the truth about the one property that makes it interesting,
     * which is that anyone can write there.
     */
    public function test_the_most_specific_directory_class_wins(): void
    {
        EdrFacetExtractor::usePlatform($this->windows);

        $this->assertSame('tmp', EdrFacetExtractor::dirclass('C:\\Windows\\Temp\\evil.exe'));
        $this->assertSame('tmp', EdrFacetExtractor::dirclass('C:\\Users\\Public\\dropper.exe'));
        $this->assertSame('etc', EdrFacetExtractor::dirclass('C:\\Windows\\System32\\drivers\\etc\\hosts'));
    }

    /** The same overlap exists on macOS, where /Library/WebServer/ lost to /Library/. */
    public function test_the_specificity_fix_applies_to_macos_too(): void
    {
        EdrFacetExtractor::usePlatform(EdrPlatformProfile::for(EdrPlatformProfile::DARWIN));

        $this->assertSame('etc', EdrFacetExtractor::dirclass('/Library/WebServer/Documents/x.php'));
        $this->assertSame('pkg', EdrFacetExtractor::dirclass('/Library/Frameworks/Foo.framework/foo'));
    }

    /** Linux has no overlapping prefixes and must be unaffected by the change. */
    public function test_linux_classification_is_unchanged(): void
    {
        EdrFacetExtractor::usePlatform(EdrPlatformProfile::for(EdrPlatformProfile::LINUX));

        $this->assertSame('sys', EdrFacetExtractor::dirclass('/usr/bin/curl'));
        $this->assertSame('tmp', EdrFacetExtractor::dirclass('/tmp/x'));
        $this->assertSame('home', EdrFacetExtractor::dirclass('/home/v/a'));
        $this->assertSame('etc', EdrFacetExtractor::dirclass('/etc/passwd'));
        $this->assertSame('pkg', EdrFacetExtractor::dirclass('/opt/x'));
    }

    /* ------------------------------------------------------------------ */
    /* Identity                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Empty because there is nothing to look up, not because the lookup
     * failed — and a caller that cannot tell those apart will treat every
     * Windows event as running under an unknown account.
     */
    public function test_windows_reports_usernames_instead_of_resolving_them(): void
    {
        $this->assertTrue($this->windows->usernameIsReported());
        $this->assertFalse(EdrPlatformProfile::for(EdrPlatformProfile::LINUX)->usernameIsReported());

        $users = $this->windows->users();
        $this->assertSame([-1 => ''], $users, 'No uid map exists on Windows');
    }

    /**
     * IIS names one identity per application pool, so the set cannot be
     * enumerated. Without the prefix, every site running under its own pool
     * loses the webshell detection while the rule goes on reporting itself as
     * active.
     */
    public function test_the_iis_pool_prefix_is_carried_because_the_names_cannot_be(): void
    {
        $this->assertSame(['iis apppool\\'], $this->windows->webAccountPrefixes());
        $this->assertSame([], EdrPlatformProfile::for(EdrPlatformProfile::LINUX)->webAccountPrefixes());

        $accounts = $this->windows->webAccounts();
        $this->assertContains('iusr', $accounts);
        $this->assertContains('defaultapppool', $accounts);
    }

    /* ------------------------------------------------------------------ */
    /* Sensor                                                              */
    /* ------------------------------------------------------------------ */

    public function test_the_etw_backend_is_selected_with_no_socket_table(): void
    {
        $tables = $this->windows->sensorTables();

        $this->assertSame('process_etw_events', $tables['process']);
        $this->assertSame('etw', $tables['backend']);
        $this->assertNull($tables['socket'], 'ETW publishes no per-connection event stream');
    }

    /**
     * A gap has to be a value. The PERSIST class exists on all three
     * platforms and would otherwise look equally covered on all three while
     * being substantially blind on one — the registry half of Windows
     * persistence is not observable through the file event stream.
     */
    public function test_the_windows_blind_spots_are_stated_rather_than_absent(): void
    {
        $this->assertSame('files_only', $this->windows->persistenceVisibility());
        $this->assertSame('complete', EdrPlatformProfile::for(EdrPlatformProfile::LINUX)->persistenceVisibility());

        $this->assertSame('not_observable', $this->windows->containerVisibility());
        $this->assertFalse($this->windows->inContainer());
    }

    /**
     * Every list the correlator reads must be populated on every platform. An
     * empty one does not throw — it removes a dimension, and the model goes on
     * scoring as though the dimension were simply never novel.
     */
    public function test_no_vocabulary_is_empty_on_any_platform(): void
    {
        foreach ([EdrPlatformProfile::LINUX, EdrPlatformProfile::DARWIN, EdrPlatformProfile::WINDOWS] as $family) {
            $profile = EdrPlatformProfile::for($family);

            foreach ([
                'directoryClasses', 'anchorImages', 'anchorKinds', 'spawnerImages',
                'transparentWrappers', 'packageManagers', 'agentBinaries', 'webAccounts',
                'fileWatchPaths', 'fileWatchExcludes',
            ] as $method) {
                $this->assertNotEmpty(
                    $profile->{$method}(),
                    "{$family}::{$method}() is empty, which removes a dimension silently"
                );
            }

            $this->assertNotEmpty($profile->criticalPaths()['files']);
            $this->assertNotEmpty($profile->criticalPaths()['prefixes']);
        }
    }

    /**
     * The agent must recognise its own processes under the name the sensor
     * actually reports, or every collection cycle scores its own osqueryd as
     * a novel execution.
     */
    public function test_the_agent_recognises_its_own_binaries_as_windows_names_them(): void
    {
        $binaries = $this->windows->agentBinaries();

        $this->assertContains('osqueryd.exe', $binaries);
        $this->assertContains('osqueryd', $binaries, 'Both spellings, since either may be reported');
    }

    /**
     * msiexec is both a package manager and a spawner, and that is not a
     * contradiction — it installs software and is a standard way to run
     * attacker-supplied code. Dropping it from either list loses something.
     */
    public function test_msiexec_is_deliberately_in_both_lists(): void
    {
        $this->assertContains('msiexec.exe', $this->windows->packageManagers());
        $this->assertContains('msiexec.exe', $this->windows->spawnerImages());
    }

    /** The living-off-the-land binaries are the ones lineage must not drop. */
    public function test_the_lolbin_set_is_present(): void
    {
        $spawners = $this->windows->spawnerImages();

        foreach (['powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe'] as $lolbin) {
            $this->assertContains($lolbin, $spawners, "{$lolbin} must keep a lineage row");
        }
    }

    /**
     * A wrapper the OS attaches by itself is not a link anyone chose, and
     * counting it as one inserts a step into every console chain.
     */
    public function test_os_attached_wrappers_are_transparent(): void
    {
        $this->assertContains('conhost.exe', $this->windows->transparentWrappers());
        $this->assertNotContains('conhost.exe', $this->windows->anchorImages());
    }
}
