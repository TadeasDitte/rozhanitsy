<?php

namespace App\Ingestion\Parsers;

use App\Ingestion\Support\CnaAffected;
use App\Ingestion\Support\Cpe23;
use App\Ingestion\VersionRangeData;
use App\Services\VersionComparator;
use Illuminate\Container\Attributes\Config;

final class NVDRangeParser implements RangeParser
{
    /**
     * @param  list<string>  $backportingProducts  vendor:product pairs, see config/matching.php
     */
    public function __construct(
        private readonly VersionComparator $comparator = new VersionComparator,
        #[Config('matching.backporting_products')] private readonly array $backportingProducts = [],
    ) {}

    public function parse(array $rawRanges): array
    {
        $ranges = [];
        $cnaEntries = [];

        foreach ($rawRanges as $configuration) {
            if (array_key_exists('cna', $configuration)) {
                array_push($cnaEntries, ...(array) $configuration['cna']);

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

        return $this->combineWithCna($ranges, $cnaEntries);
    }

    /**
     * A CPE match holds one contiguous range, so a fix shipped on several release
     * branches is lossy there, but the CNA's own `affected` entry is often just as
     * coarse ("< 7.1.2" while NVD lists every backport). Per vendor / product the
     * source that separates release branches wins, both when both do, and the
     * CNA when neither does. A record NVD has not analysed yet has no CPE ranges
     * at all, its CNA ranges are filed under the CNA's own product names.
     *
     * A wrong range costs a false alarm, so CNA ranges NVD does not back up are
     * kept as low confidence: the CNA half of a combined set, everything-affected
     * defaults, and coarse ranges of products that backport fixes.
     *
     * @param  list<VersionRangeData>  $ranges
     * @param  array<int, mixed>  $cnaEntries
     * @return list<VersionRangeData>
     */
    private function combineWithCna(array $ranges, array $cnaEntries): array
    {
        $cnas = array_values(array_filter(array_map(
            fn (mixed $entry): ?CnaAffected => is_array($entry) ? CnaAffected::parse($entry) : null,
            $cnaEntries,
        )));

        if ($cnas === []) {
            return $ranges;
        }

        /** @var array<string, list<VersionRangeData>> $cpeRanges the replaceable CPE ranges of each vendor / product */
        $cpeRanges = [];

        foreach ($ranges as $range) {
            if ($range->product !== null && $range->versionScope !== 'na') {
                $cpeRanges[$range->vendor.'|'.$range->product][] = $range;
            }
        }

        if ($ranges === []) {
            return $this->cnaOnlyRanges($cnas);
        }

        if ($cpeRanges === []) {
            return $ranges;
        }

        /** @var array<string, list<VersionRangeData>> $cnaRanges */
        $cnaRanges = [];

        foreach ($cnas as $cna) {
            foreach ($cpeRanges as $key => $group) {
                $template = $group[0];

                if (! $cna->isAbout($template->vendor, (string) $template->product)) {
                    continue;
                }

                foreach ($this->consistentBounds($cna->ranges) as $bounds) {
                    $cnaRanges[$key][] = $this->cnaRange($bounds, $template->type, $template->vendor, $template->product, $template->plugsInto, $cna->isAffectedByDefault ? 'low' : 'high');
                }
            }
        }

        $kept = array_values(array_filter(
            $ranges,
            fn (VersionRangeData $range): bool => $range->versionScope === 'na' || ! isset($cnaRanges[$range->vendor.'|'.$range->product]),
        ));

        foreach ($cnaRanges as $key => $fromCna) {
            array_push($kept, ...$this->choose($cpeRanges[$key], $fromCna));
        }

        return $kept;
    }

    /**
     * @param  list<VersionRangeData>  $fromCpe
     * @param  list<VersionRangeData>  $fromCna
     * @return list<VersionRangeData>
     */
    private function choose(array $fromCpe, array $fromCna): array
    {
        $bounded = array_values(array_filter($fromCpe, fn (VersionRangeData $range): bool => $range->versionScope === 'range'));
        $confident = array_values(array_filter($fromCna, fn (VersionRangeData $range): bool => $range->confidence === 'high'));
        $doubtful = array_values(array_filter($fromCna, fn (VersionRangeData $range): bool => $range->confidence === 'low'));

        if ($confident === []) {
            return [...$fromCpe, ...$doubtful];
        }

        if ($bounded === []) {
            return $fromCna;
        }

        return match ([$this->isPerBranch($bounded), $this->isPerBranch($confident)]) {
            [true, true] => [...$bounded, ...array_map($this->withLowConfidence(...), $confident), ...$doubtful],
            [true, false] => [...$fromCpe, ...$doubtful],
            default => $fromCna,
        };
    }

    private function withLowConfidence(VersionRangeData $range): VersionRangeData
    {
        return new VersionRangeData(
            type: $range->type,
            ecosystem: $range->ecosystem,
            packageManager: $range->packageManager,
            vendor: $range->vendor,
            product: $range->product,
            versionInclStart: $range->versionInclStart,
            versionExclStart: $range->versionExclStart,
            versionInclEnd: $range->versionInclEnd,
            versionExclEnd: $range->versionExclEnd,
            plugsInto: $range->plugsInto,
            raw: $range->raw,
            versionScope: $range->versionScope,
            confidence: 'low',
        );
    }

    /**
     * Whether the ranges tell release branches apart, i.e. any of them starts
     * somewhere other than the first version.
     *
     * @param  list<VersionRangeData>  $ranges
     */
    private function isPerBranch(array $ranges): bool
    {
        foreach ($ranges as $range) {
            if ($range->versionInclStart !== null || $range->versionExclStart !== null) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<CnaAffected>  $cnas
     * @return list<VersionRangeData>
     */
    private function cnaOnlyRanges(array $cnas): array
    {
        $ranges = [];

        foreach ($cnas as $cna) {
            if ($cna->product === null) {
                continue;
            }

            foreach ($this->consistentBounds($cna->ranges) as $bounds) {
                $isCoarseBackport = $bounds['startIncl'] === null && $bounds['startExcl'] === null
                    && in_array($cna->vendor.':'.$cna->product, $this->backportingProducts, true);

                $ranges[] = $this->cnaRange($bounds, 'a', $cna->vendor, $cna->product, null, $cna->isAffectedByDefault || $isCoarseBackport ? 'low' : 'high');
            }
        }

        return $ranges;
    }

    /**
     * Drops ranges whose start lies past their end, such as a mistyped "4.70" for
     * "4.7.0", which would otherwise hide every version of the branch.
     *
     * @param  list<array<string, ?string>>  $ranges
     * @return list<array<string, ?string>>
     */
    private function consistentBounds(array $ranges): array
    {
        return array_values(array_filter($ranges, function (array $bounds): bool {
            $start = $bounds['startIncl'] ?? $bounds['startExcl'];
            $end = $bounds['endIncl'] ?? $bounds['endExcl'];

            if ($start === null || $end === null) {
                return true;
            }

            $order = $this->comparator->compare($start, $end);

            return $bounds['startIncl'] !== null && $bounds['endIncl'] !== null ? $order <= 0 : $order < 0;
        }));
    }

    /**
     * @param  array<string, ?string>  $bounds
     * @param  'a'|'h'|'o'|'u'  $type
     * @param  'high'|'low'  $confidence
     */
    private function cnaRange(array $bounds, string $type, ?string $vendor, ?string $product, ?string $plugsInto, string $confidence): VersionRangeData
    {
        return new VersionRangeData(
            type: $type,
            ecosystem: null,
            packageManager: null,
            vendor: $vendor,
            product: $product,
            versionInclStart: $bounds['startIncl'],
            versionExclStart: $bounds['startExcl'],
            versionInclEnd: $bounds['endIncl'],
            versionExclEnd: $bounds['endExcl'],
            plugsInto: $plugsInto,
            raw: 'cna:'.$bounds['raw'],
            confidence: $confidence,
        );
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
                [$startIncl, $endIncl, $endExcl] = $this->exactVersion($cpe);
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
     * The bounds of a CPE naming one version. Its update field narrows that to a
     * pre-release ("5.8:beta1"), or to all pre-releases of a kind ("5.8:beta*",
     * every 5.8 beta and release candidate but not 5.8 itself).
     *
     * @return array{string, ?string, ?string} inclusive start, inclusive end, exclusive end
     */
    private function exactVersion(Cpe23 $cpe): array
    {
        if (! $this->isConcrete($cpe->update)) {
            return [$cpe->version, $cpe->version, null];
        }

        $isWildcard = str_ends_with($cpe->update, '*');
        $version = $cpe->version.'-'.rtrim($cpe->update, '*');

        if ($isWildcard && $this->comparator->compare($version, $cpe->version) < 0) {
            return [$version, null, $cpe->version];
        }

        return [$version, $version, null];
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
