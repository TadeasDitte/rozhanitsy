<?php

namespace App\Services;

use App\Models\VersionRange;
use App\Services\Versioning\ApkVersionScheme;
use App\Services\Versioning\DpkgVersionScheme;
use App\Services\Versioning\RpmVersionScheme;
use App\Services\Versioning\VersionScheme;

/**
 * Ecosystem-agnostic version ordering for matching against version_ranges.
 *
 * A version is split into an optional epoch ("1:"), a numeric release segment
 * ("1.2.3") and a suffix of qualifier / number tokens ("-rc.1", ".post2").
 * Release segments compare numerically with zero padding (1.0 == 1.0.0).
 * Suffix tokens compare by rank: pre-release qualifiers (dev < alpha < beta <
 * unknown words < rc) sort before the bare release, numbers and post-release
 * qualifiers (post, patch, sp, ...) sort after it. A lone trailing letter glued
 * to a number ("1.1.1a", OpenSSL style) is treated as a post-release.
 * Leading "v" and "+build" metadata are ignored.
 *
 * Distro ecosystems (Debian, Ubuntu, Alpine, Red Hat, ...) order versions by their
 * package manager's own rules instead, see ECOSYSTEM_SCHEMES. Any other
 * ecosystem, and NVD data without one, uses the generic ordering above.
 */
final class VersionComparator
{
    private const int RANK_RELEASE = 0;

    private const int RANK_UNKNOWN_WORD = -2;

    private const int RANK_NUMBER = 1;

    private const int RANK_POST = 2;

    /**
     * @var array<string, int>
     */
    private const array QUALIFIER_RANKS = [
        'dev' => -6,
        'snapshot' => -6,
        'alpha' => -5,
        'a' => -5,
        'beta' => -4,
        'b' => -4,
        'milestone' => -3,
        'm' => -3,
        'pre' => -3,
        'preview' => -3,
        'rc' => -1,
        'c' => -1,
        'cr' => -1,
        'ga' => self::RANK_RELEASE,
        'final' => self::RANK_RELEASE,
        'release' => self::RANK_RELEASE,
        'post' => self::RANK_POST,
        'patch' => self::RANK_POST,
        'p' => self::RANK_POST,
        'pl' => self::RANK_POST,
        'sp' => self::RANK_POST,
        'rev' => self::RANK_POST,
        'r' => self::RANK_POST,
    ];

    /**
     * OSV ecosystem name before the first colon (lowercase) => package manager ordering.
     *
     * @var array<string, class-string<VersionScheme>>
     */
    private const array ECOSYSTEM_SCHEMES = [
        'debian' => DpkgVersionScheme::class,
        'ubuntu' => DpkgVersionScheme::class,
        'red hat' => RpmVersionScheme::class,
        'rocky linux' => RpmVersionScheme::class,
        'almalinux' => RpmVersionScheme::class,
        'suse' => RpmVersionScheme::class,
        'opensuse' => RpmVersionScheme::class,
        'mageia' => RpmVersionScheme::class,
        'openeuler' => RpmVersionScheme::class,
        'photon os' => RpmVersionScheme::class,
        'azure linux' => RpmVersionScheme::class,
        'alpine' => ApkVersionScheme::class,
        'alpaquita' => ApkVersionScheme::class,
        'chainguard' => ApkVersionScheme::class,
        'wolfi' => ApkVersionScheme::class,
        'minimos' => ApkVersionScheme::class,
    ];

    /**
     * @var array<class-string<VersionScheme>, VersionScheme>
     */
    private array $schemes = [];

    /**
     * @param  ?string  $ecosystem  the OSV ecosystem both versions belong to, e.g. "Debian:12"
     * @return int -1 when $a < $b, 0 when equal, 1 when $a > $b
     */
    public function compare(string $a, string $b, ?string $ecosystem = null): int
    {
        return $this->schemeFor($ecosystem)?->compare($a, $b) ?? $this->compareGeneric($a, $b);
    }

    public function isInRange(string $version, VersionRange $range): bool
    {
        $ecosystem = $range->ecosystem;

        return ($range->version_incl_start === null || $this->compare($version, $range->version_incl_start, $ecosystem) >= 0)
            && ($range->version_excl_start === null || $this->compare($version, $range->version_excl_start, $ecosystem) > 0)
            && ($range->version_incl_end === null || $this->compare($version, $range->version_incl_end, $ecosystem) <= 0)
            && ($range->version_excl_end === null || $this->compare($version, $range->version_excl_end, $ecosystem) < 0);
    }

    private function schemeFor(?string $ecosystem): ?VersionScheme
    {
        if ($ecosystem === null) {
            return null;
        }

        $family = strtolower(explode(':', $ecosystem, 2)[0]);
        $scheme = self::ECOSYSTEM_SCHEMES[$family] ?? null;

        return $scheme === null ? null : ($this->schemes[$scheme] ??= new $scheme);
    }

    private function compareGeneric(string $a, string $b): int
    {
        $left = $this->normalize($a);
        $right = $this->normalize($b);

        return $this->compareNumbers($left['epoch'], $right['epoch'])
            ?: $this->compareRelease($left['release'], $right['release'])
            ?: $this->compareSuffix($left['suffix'], $right['suffix']);
    }

    /**
     * @return array{epoch: string, release: list<string>, suffix: list<array{rank: int, value: string}>}
     */
    private function normalize(string $version): array
    {
        $version = strtolower(trim($version));
        $version = preg_replace('/\+.*$/', '', $version) ?? $version;
        $version = preg_replace('/^v(?=\d)/', '', $version) ?? $version;

        $epoch = '0';

        if (preg_match('/^(\d+):(.*)$/', $version, $matches) === 1) {
            $epoch = $matches[1];
            $version = $matches[2];
        }

        preg_match('/^\d+(?:\.\d+)*/', $version, $matches);
        $releaseText = $matches[0] ?? '';
        $release = $releaseText === '' ? [] : explode('.', $releaseText);
        $remainder = substr($version, strlen($releaseText));

        return [
            'epoch' => $epoch,
            'release' => $release,
            'suffix' => $this->suffixTokens($remainder),
        ];
    }

    /**
     * @return list<array{rank: int, value: string}>
     */
    private function suffixTokens(string $remainder): array
    {
        if (preg_match('/^[a-z]$/', $remainder) === 1) {
            return [['rank' => self::RANK_POST, 'value' => $remainder]];
        }

        preg_match_all('/\d+|[a-z]+/', $remainder, $matches);

        return array_map(function (string $token): array {
            if (ctype_digit($token)) {
                return ['rank' => self::RANK_NUMBER, 'value' => $token];
            }

            return ['rank' => self::QUALIFIER_RANKS[$token] ?? self::RANK_UNKNOWN_WORD, 'value' => $token];
        }, $matches[0]);
    }

    /**
     * @param  list<string>  $left
     * @param  list<string>  $right
     */
    private function compareRelease(array $left, array $right): int
    {
        $length = max(count($left), count($right));

        for ($i = 0; $i < $length; $i++) {
            $result = $this->compareNumbers($left[$i] ?? '0', $right[$i] ?? '0');

            if ($result !== 0) {
                return $result;
            }
        }

        return 0;
    }

    /**
     * @param  list<array{rank: int, value: string}>  $left
     * @param  list<array{rank: int, value: string}>  $right
     */
    private function compareSuffix(array $left, array $right): int
    {
        $release = ['rank' => self::RANK_RELEASE, 'value' => ''];
        $length = max(count($left), count($right));

        for ($i = 0; $i < $length; $i++) {
            $a = $left[$i] ?? $release;
            $b = $right[$i] ?? $release;

            if ($a['rank'] !== $b['rank']) {
                return $a['rank'] <=> $b['rank'];
            }

            $result = match ($a['rank']) {
                self::RANK_RELEASE => 0,
                self::RANK_NUMBER => $this->compareNumbers($a['value'], $b['value']),
                default => strcmp($a['value'], $b['value']) <=> 0,
            };

            if ($result !== 0) {
                return $result;
            }
        }

        return 0;
    }

    /**
     * Compares digit strings of arbitrary length without integer overflow.
     */
    private function compareNumbers(string $a, string $b): int
    {
        $a = ltrim($a, '0');
        $b = ltrim($b, '0');

        return (strlen($a) <=> strlen($b)) ?: (strcmp($a, $b) <=> 0);
    }
}
