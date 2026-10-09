<?php

namespace App\Ingestion\Parsers;

use App\Ingestion\VersionRangeData;

final class OSVRangeParser implements RangeParser
{
    public function parse(array $rawRanges): array
    {
        $ranges = [];

        foreach ($rawRanges as $affected) {
            $package = $affected['package'] ?? [];
            $ecosystem = $this->stringOrNull($package['ecosystem'] ?? null);
            $product = $this->stringOrNull($package['name'] ?? null);
            $purl = $this->stringOrNull($package['purl'] ?? null);
            $packageManager = $purl !== null ? $this->packageManagerFromPurl($purl) : null;
            $vendor = $purl !== null ? $this->vendorFromPurl($purl) : null;

            // Packagist names are case insensitive and composer.lock spells them in lowercase
            if ($ecosystem === 'Packagist') {
                $product = $product !== null ? mb_strtolower($product) : null;
                $vendor = $vendor !== null ? mb_strtolower($vendor) : null;
            }

            foreach ($affected['ranges'] ?? [] as $range) {
                $rangeType = $range['type'] ?? null;

                if ($rangeType !== 'SEMVER' && $rangeType !== 'ECOSYSTEM') {
                    continue;
                }

                $raw = trim(($purl ?? $product ?? '').' '.(json_encode($range, JSON_UNESCAPED_SLASHES) ?: ''));

                foreach ($this->intervals($range['events'] ?? []) as $interval) {
                    $ranges[] = new VersionRangeData(
                        type: 'a',
                        ecosystem: $ecosystem,
                        packageManager: $packageManager,
                        vendor: $vendor,
                        product: $product,
                        versionInclStart: $interval['introduced'],
                        versionExclStart: null,
                        versionInclEnd: $interval['last_affected'],
                        versionExclEnd: $interval['fixed'],
                        plugsInto: null,
                        raw: $raw !== '' ? $raw : null,
                    );
                }
            }
        }

        return $ranges;
    }

    /**
     * @param  array<int, array<string, mixed>>  $events
     * @return list<array{introduced: ?string, fixed: ?string, last_affected: ?string}>
     */
    private function intervals(array $events): array
    {
        $intervals = [];
        $open = null;

        foreach ($events as $event) {
            if (array_key_exists('introduced', $event)) {
                if ($open !== null) {
                    $intervals[] = $open;
                }

                $introduced = (string) $event['introduced'];

                $open = [
                    'introduced' => $introduced === '0' ? null : $introduced,
                    'fixed' => null,
                    'last_affected' => null,
                ];

                continue;
            }

            if ($open === null) {
                continue;
            }

            if (array_key_exists('fixed', $event)) {
                $open['fixed'] = (string) $event['fixed'];
                $intervals[] = $open;
                $open = null;

                continue;
            }

            if (array_key_exists('last_affected', $event)) {
                $open['last_affected'] = (string) $event['last_affected'];
                $intervals[] = $open;
                $open = null;
            }
        }

        if ($open !== null) {
            $intervals[] = $open;
        }

        return $intervals;
    }

    private function vendorFromPurl(string $purl): ?string
    {
        $segments = $this->purlSegments($purl);

        if (count($segments) < 3) {
            return null;
        }

        $namespace = implode('/', array_slice($segments, 1, count($segments) - 2));

        return rawurldecode($namespace);
    }

    private function packageManagerFromPurl(string $purl): ?string
    {
        return $this->purlSegments($purl)[0] ?? null;
    }

    /**
     * @return list<string>
     */
    private function purlSegments(string $purl): array
    {
        $body = preg_replace('#^pkg:#', '', $purl) ?? $purl;
        $body = preg_split('/[@?#]/', $body)[0] ?? $body;

        return array_values(array_filter(explode('/', $body), static fn (string $s): bool => $s !== ''));
    }

    private function stringOrNull(mixed $value): ?string
    {
        return (is_string($value) && $value !== '') ? $value : null;
    }
}
