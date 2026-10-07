<?php

namespace App\Ingestion\Support;

use InvalidArgumentException;

/**
 * One `affected` entry of a CVE record as the CNA (the vendor or its advisory
 * database) wrote it, reduced to the product names it mentions and the version
 * ranges it calls affected. Entries that cannot be read as plain ranges are not
 * represented at all, see parse().
 *
 * @phpstan-type Bounds array{startIncl: ?string, startExcl: ?string, endIncl: ?string, endExcl: ?string, raw: string}
 */
final readonly class CnaAffected
{
    private const array PLACEHOLDERS = ['', 'n/a', 'na', 'unspecified', 'unknown', 'none', '*', '-'];

    /**
     * @param  list<string>  $names  normalized vendor, product, package and module names
     * @param  list<Bounds>  $ranges
     * @param  ?string  $vendor  CPE style vendor to file the ranges under when no CPE range names the product
     * @param  ?string  $product  CPE style product, see $vendor
     * @param  bool  $isAffectedByDefault  whether the ranges come from an everything-affected default rather than listed versions
     */
    private function __construct(
        public array $names,
        public array $ranges,
        public ?string $vendor,
        public ?string $product,
        public bool $isAffectedByDefault = false,
    ) {}

    /**
     * Returns null unless every affected version is a readable range. An entry
     * that declares everything affected by default is read as one open range,
     * cut short by an unaffected "X and later" when it has one.
     *
     * @param  array<string, mixed>  $entry
     */
    public static function parse(array $entry): ?self
    {
        $isAffectedByDefault = ($entry['defaultStatus'] ?? null) === 'affected';
        $ranges = $isAffectedByDefault
            ? self::affectedByDefault((array) ($entry['versions'] ?? []))
            : self::affectedRanges((array) ($entry['versions'] ?? []));

        if ($ranges === null || $ranges === []) {
            return null;
        }

        $names = [];

        foreach ([$entry['vendor'] ?? null, $entry['product'] ?? null, $entry['packageName'] ?? null, ...(array) ($entry['modules'] ?? [])] as $name) {
            if (is_string($name) && ! self::isPlaceholder($name)) {
                $names[] = self::normalize($name);
            }
        }

        if ($names === []) {
            return null;
        }

        [$vendor, $product] = self::cpeName($entry);

        return new self(array_values(array_unique($names)), $ranges, $vendor, $product, $isAffectedByDefault);
    }

    /**
     * Whether the entry is about a CPE vendor / product, comparing names without
     * case and punctuation ("Apache ORC" is `apache` + `orc`).
     */
    public function isAbout(?string $vendor, string $product): bool
    {
        $names = [self::normalize($product)];

        if ($vendor !== null) {
            $names[] = self::normalize($vendor.$product);
        }

        return array_intersect($names, $this->names) !== [];
    }

    /**
     * @param  array<int, mixed>  $versions
     * @return list<Bounds>|null
     */
    private static function affectedRanges(array $versions): ?array
    {
        $ranges = [];

        foreach ($versions as $item) {
            if (! is_array($item) || ($item['status'] ?? null) !== 'affected') {
                continue;
            }

            $bounds = self::bounds($item);

            if ($bounds === null) {
                return null;
            }

            $ranges[] = $bounds;
        }

        return $ranges;
    }

    /**
     * Everything is affected except what the entry lists as unaffected. Only an
     * open ended unaffected tail ("X and later") can be expressed as a range,
     * the affected items add nothing to an everything-affected default.
     *
     * @param  array<int, mixed>  $versions
     * @return list<Bounds>|null
     */
    private static function affectedByDefault(array $versions): ?array
    {
        $fixedIn = [];

        foreach ($versions as $item) {
            if (! is_array($item) || ($item['status'] ?? null) !== 'unaffected') {
                continue;
            }

            $version = is_string($item['version'] ?? null) ? trim($item['version']) : '';
            $isOpenEnded = trim((string) ($item['lessThan'] ?? $item['lessThanOrEqual'] ?? '')) === '*';

            if (! $isOpenEnded || ! self::isVersion($version)) {
                return null;
            }

            $fixedIn[] = $version;
        }

        if (count($fixedIn) > 1) {
            return null;
        }

        return [[
            'startIncl' => null,
            'startExcl' => null,
            'endIncl' => null,
            'endExcl' => $fixedIn[0] ?? null,
            'raw' => (string) json_encode(['defaultStatus' => 'affected', 'versions' => $versions], JSON_UNESCAPED_SLASHES),
        ]];
    }

    /**
     * The vendor and product to file the ranges under: the entry's own CPE when
     * it lists one, else the package name or a slug of the product name.
     *
     * @param  array<string, mixed>  $entry
     * @return array{?string, ?string}
     */
    private static function cpeName(array $entry): array
    {
        foreach ((array) ($entry['cpes'] ?? []) as $criteria) {
            try {
                $cpe = is_string($criteria) ? Cpe23::parse($criteria) : null;
            } catch (InvalidArgumentException) {
                $cpe = null;
            }

            if ($cpe !== null && ! self::isPlaceholder($cpe->product)) {
                return [self::isPlaceholder($cpe->vendor) ? null : $cpe->vendor, $cpe->product];
            }
        }

        $vendor = is_string($entry['vendor'] ?? null) && ! self::isPlaceholder($entry['vendor'])
            ? self::normalize($entry['vendor'])
            : null;

        foreach ([$entry['packageName'] ?? null, $entry['product'] ?? null] as $name) {
            if (is_string($name) && ! self::isPlaceholder($name)) {
                return [$vendor, self::slug($name)];
            }
        }

        return [$vendor, null];
    }

    /**
     * @param  array<string, mixed>  $item
     * @return Bounds|null
     */
    private static function bounds(array $item): ?array
    {
        $version = is_string($item['version'] ?? null) ? trim($item['version']) : '';
        $raw = (string) json_encode($item, JSON_UNESCAPED_SLASHES);
        $lessThan = self::upperBound($item['lessThan'] ?? null);
        $lessThanOrEqual = self::upperBound($item['lessThanOrEqual'] ?? null);

        if ($lessThan === false || $lessThanOrEqual === false) {
            return null;
        }

        if (isset($item['lessThan']) || isset($item['lessThanOrEqual'])) {
            $isOpenStart = $version === '0' || $version === '*' || $version === $lessThan;

            if (! $isOpenStart && ! self::isVersion($version)) {
                return null;
            }

            return [
                // WPScan writes "< X" as version X, lessThan X, Wordfence as version *
                'startIncl' => $isOpenStart ? null : $version,
                'startExcl' => null,
                'endIncl' => $lessThanOrEqual,
                'endExcl' => $lessThan,
                'raw' => $raw,
            ];
        }

        if (self::isVersion($version)) {
            return $version === '0'
                ? null
                : ['startIncl' => $version, 'startExcl' => null, 'endIncl' => $version, 'endExcl' => null, 'raw' => $raw];
        }

        return self::expression($version, $raw);
    }

    /**
     * @return string|false|null a version, null for "no bound" ("*"), false when unreadable
     */
    private static function upperBound(mixed $value): string|false|null
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            return false;
        }

        $value = trim($value);

        return match (true) {
            $value === '*' => null,
            self::isVersion($value) => $value,
            default => false,
        };
    }

    /**
     * Comma separated comparators such as ">= 3.1.0, < 3.1.2".
     *
     * @return Bounds|null
     */
    private static function expression(string $text, string $raw): ?array
    {
        $bounds = ['startIncl' => null, 'startExcl' => null, 'endIncl' => null, 'endExcl' => null, 'raw' => $raw];
        $seen = [];

        foreach (explode(',', $text) as $part) {
            if (preg_match('/^\s*(<=|>=|<|>|=)\s*(\S+)\s*$/', $part, $matches) !== 1 || ! self::isVersion($matches[2])) {
                return null;
            }

            [, $operator, $version] = $matches;
            $keys = match ($operator) {
                '>=' => ['startIncl'],
                '>' => ['startExcl'],
                '<=' => ['endIncl'],
                '<' => ['endExcl'],
                default => ['startIncl', 'endIncl'],
            };

            foreach ($keys as $key) {
                if (isset($seen[$key])) {
                    return null;
                }

                $seen[$key] = true;
                $bounds[$key] = $version;
            }
        }

        return $bounds;
    }

    private static function isVersion(string $value): bool
    {
        return ! self::isPlaceholder($value)
            && preg_match('/^[A-Za-z0-9][\w.+:~\-]*$/', $value) === 1
            && preg_match('/\d/', $value) === 1;
    }

    private static function isPlaceholder(string $value): bool
    {
        return in_array(strtolower(trim($value)), self::PLACEHOLDERS, true);
    }

    private static function normalize(string $name): string
    {
        return preg_replace('/[^a-z0-9]+/', '', strtolower($name)) ?? '';
    }

    /**
     * "WP GDPR Compliance" becomes `wp-gdpr-compliance`, the shape of a plugin slug.
     */
    private static function slug(string $name): string
    {
        return trim(preg_replace('/[^a-z0-9_.\/]+/', '-', strtolower(trim($name))) ?? '', '-');
    }
}
