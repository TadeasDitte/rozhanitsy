<?php

namespace App\Ingestion\Parsers;

use App\Ingestion\Support\CnaAffected;
use App\Ingestion\Support\Cpe23;
use App\Ingestion\VersionRangeData;

final class NVDRangeParser implements RangeParser
{
    public function parse(array $rawRanges): array
    {
        $ranges = [];
        $cnaEntries = [];

        foreach ($rawRanges as $configuration) {
            if (array_key_exists('cna', $configuration)) {
                $cnaEntries = [...$cnaEntries, ...(array) $configuration['cna']];

                continue;
            }

            $nodes = $configuration['nodes'] ?? [];
            $platformNodes = $this->platformNodes($configuration);
            $configurationPlugsInto = $this->firstProduct($platformNodes);

            foreach ($nodes as $index => $node) {
                if (array_key_exists($index, $platformNodes)) {
                    continue;
                }

                $plugsInto = $this->resolvePlugsInto($node) ?? $configurationPlugsInto;

                foreach ($this->vulnerableMatches($node) as $match) {
                    $range = $this->buildRange($match, $plugsInto);

                    if ($range !== null) {
                        $ranges[] = $range;
                    }
                }
            }
        }

        return $this->preferCna($ranges, $cnaEntries);
    }

    /**
     * A CPE match holds one contiguous range, so a fix shipped on several release
     * branches is lossy there. Where the CNA's own `affected` entry is a plain
     * list of ranges for the same product, those replace the CPE ranges.
     *
     * @param  list<VersionRangeData>  $ranges
     * @param  array<int, mixed>  $cnaEntries
     * @return list<VersionRangeData>
     */
    private function preferCna(array $ranges, array $cnaEntries): array
    {
        /** @var array<string, array{template: VersionRangeData, bounds: list<array<string, ?string>>}> $replacements */
        $replacements = [];

        foreach ($cnaEntries as $entry) {
            $cna = is_array($entry) ? CnaAffected::parse($entry) : null;

            if ($cna === null) {
                continue;
            }

            foreach ($ranges as $range) {
                if ($range->product === null || $range->versionScope === 'na' || ! $cna->isAbout($range->vendor, $range->product)) {
                    continue;
                }

                $key = $range->vendor.'|'.$range->product;
                $replacements[$key] ??= ['template' => $range, 'bounds' => []];
                $replacements[$key]['bounds'] = [...$replacements[$key]['bounds'], ...$cna->ranges];
            }
        }

        if ($replacements === []) {
            return $ranges;
        }

        $kept = array_values(array_filter(
            $ranges,
            fn (VersionRangeData $range): bool => $range->versionScope === 'na' || ! isset($replacements[$range->vendor.'|'.$range->product]),
        ));

        foreach ($replacements as $replacement) {
            foreach ($replacement['bounds'] as $bounds) {
                $kept[] = new VersionRangeData(
                    type: $replacement['template']->type,
                    ecosystem: null,
                    packageManager: null,
                    vendor: $replacement['template']->vendor,
                    product: $replacement['template']->product,
                    versionInclStart: $bounds['startIncl'],
                    versionExclStart: $bounds['startExcl'],
                    versionInclEnd: $bounds['endIncl'],
                    versionExclEnd: $bounds['endExcl'],
                    plugsInto: $replacement['template']->plugsInto,
                    raw: 'cna:'.$bounds['raw'],
                );
            }
        }

        return $kept;
    }

    /**
     * @param  array<string, mixed>  $match
     */
    private function buildRange(array $match, ?string $plugsInto): ?VersionRangeData
    {
        $criteria = $match['criteria'] ?? null;

        if (! is_string($criteria)) {
            return null;
        }

        $cpe = Cpe23::parse($criteria);

        $startIncl = $this->bound($match['versionStartIncluding'] ?? null);
        $startExcl = $this->bound($match['versionStartExcluding'] ?? null);
        $endIncl = $this->bound($match['versionEndIncluding'] ?? null);
        $endExcl = $this->bound($match['versionEndExcluding'] ?? null);

        $hasBound = $startIncl !== null || $startExcl !== null || $endIncl !== null || $endExcl !== null;
        $versionScope = 'range';

        if (! $hasBound) {
            if ($this->isConcrete($cpe->version)) {
                $startIncl = $cpe->version;
                $endIncl = $cpe->version;
            } else {
                $versionScope = $cpe->version === '-' ? 'na' : 'any';
            }
        }

        return new VersionRangeData(
            type: $this->mapPart($cpe->part),
            ecosystem: null,
            packageManager: null,
            vendor: $this->attribute($cpe->vendor),
            product: $this->attribute($cpe->product),
            versionInclStart: $startIncl,
            versionExclStart: $startExcl,
            versionInclEnd: $endIncl,
            versionExclEnd: $endExcl,
            plugsInto: $plugsInto ?? $this->attribute($cpe->targetSw),
            raw: $criteria,
            versionScope: $versionScope,
        );
    }

    /**
     * @param  array<string, mixed>  $configuration
     * @return array<int, array<string, mixed>>
     */
    private function platformNodes(array $configuration): array
    {
        $nodes = $configuration['nodes'] ?? [];

        if (($configuration['operator'] ?? null) !== 'AND' || count($nodes) < 2) {
            return [];
        }

        $versionedNodes = array_filter($nodes, fn (array $node): bool => $this->hasVersionedMatch($node));

        return array_filter($nodes, fn (array $node): bool => $this->vulnerableMatches($node) === []
            || ($versionedNodes !== [] && ! $this->hasVersionedMatch($node)));
    }

    /**
     * @param  array<string, mixed>  $node
     */
    private function hasVersionedMatch(array $node): bool
    {
        foreach ($this->vulnerableMatches($node) as $match) {
            foreach (['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'] as $key) {
                if ($this->bound($match[$key] ?? null) !== null) {
                    return true;
                }
            }

            if (is_string($match['criteria'] ?? null) && $this->isConcrete(Cpe23::parse($match['criteria'])->version)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string, mixed>  $node
     * @return list<array<string, mixed>>
     */
    private function vulnerableMatches(array $node): array
    {
        return array_values(array_filter(
            $node['cpeMatch'] ?? [],
            fn (array $match): bool => ($match['vulnerable'] ?? false) === true,
        ));
    }

    /**
     * @param  array<int, array<string, mixed>>  $nodes
     */
    private function firstProduct(array $nodes): ?string
    {
        foreach ($nodes as $node) {
            foreach ($node['cpeMatch'] ?? [] as $match) {
                $criteria = $match['criteria'] ?? null;
                $product = is_string($criteria) ? $this->attribute(Cpe23::parse($criteria)->product) : null;

                if ($product !== null) {
                    return $product;
                }
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $node
     */
    private function resolvePlugsInto(array $node): ?string
    {
        if (($node['operator'] ?? null) !== 'AND') {
            return null;
        }

        $nonVulnerable = array_filter($node['cpeMatch'] ?? [], fn (array $match): bool => ($match['vulnerable'] ?? false) !== true);

        return $this->firstProduct([['cpeMatch' => $nonVulnerable]]);
    }

    /**
     * @return 'a'|'h'|'o'|'u'
     */
    private function mapPart(string $part): string
    {
        return match ($part) {
            'a', 'h', 'o' => $part,
            default => 'u',
        };
    }

    private function attribute(string $value): ?string
    {
        return ($value === '*' || $value === '-' || $value === '') ? null : $value;
    }

    private function bound(mixed $value): ?string
    {
        return ($value === null || $value === '') ? null : (string) $value;
    }

    private function isConcrete(string $version): bool
    {
        return $version !== '*' && $version !== '-' && $version !== '';
    }
}
