<?php

namespace App\Ingestion\Support;

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
     */
    private function __construct(public array $names, public array $ranges) {}

    /**
     * Returns null unless every affected version is a readable range and the
     * entry does not declare everything affected by default.
     *
     * @param  array<string, mixed>  $entry
     */
    public static function parse(array $entry): ?self
    {
        if (($entry['defaultStatus'] ?? null) === 'affected') {
            return null;
        }

        $ranges = [];

        foreach ((array) ($entry['versions'] ?? []) as $item) {
            if (! is_array($item) || ($item['status'] ?? null) !== 'affected') {
                continue;
            }

            $bounds = self::bounds($item);

            if ($bounds === null) {
                return null;
            }

            $ranges[] = $bounds;
        }

        if ($ranges === []) {
            return null;
        }

        $names = [];

        foreach ([$entry['vendor'] ?? null, $entry['product'] ?? null, $entry['packageName'] ?? null, ...(array) ($entry['modules'] ?? [])] as $name) {
            if (is_string($name) && ! self::isPlaceholder($name)) {
                $names[] = self::normalize($name);
            }
        }

        return $names === [] ? null : new self(array_values(array_unique($names)), $ranges);
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
            if (! self::isVersion($version)) {
                return null;
            }

            return [
                'startIncl' => $version === '0' ? null : $version,
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
}
