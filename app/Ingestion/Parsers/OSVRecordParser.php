<?php

namespace App\Ingestion\Parsers;

use App\Ingestion\ParsedRecordData;
use App\Ingestion\Support\Cvss;
use App\Ingestion\Support\Severity;
use Carbon\Carbon;

final class OSVRecordParser implements SourceRecordParser
{
    public function parseOne(array $rawPayload): ?ParsedRecordData
    {
        if (empty($rawPayload['id'])) {
            return null;
        }

        [$score, $vector, $version, $severity] = $this->extractCvss($rawPayload);

        return new ParsedRecordData(
            externalId: $rawPayload['id'],
            aliases: $rawPayload['aliases'] ?? [],
            cvssScore: $score,
            cvssVector: $vector,
            cvssVersion: $version,
            cvssSeverity: $severity,
            description: $this->extractDescription($rawPayload),
            publishedAt: $this->parseDate($rawPayload['published'] ?? null),
            lastModifiedAt: $this->parseDate($rawPayload['modified'] ?? null),
            weaknesses: $rawPayload['database_specific']['cwe_ids'] ?? [],
            references: $this->extractReferences($rawPayload['references'] ?? []),
            status: isset($rawPayload['withdrawn']) ? 'withdrawn' : null,
            knownExploited: false,
            rawRanges: $rawPayload['affected'] ?? [],
        );
    }

    /**
     * @param  array<string, mixed>  $rawPayload
     * @return array{0: ?float, 1: ?string, 2: ?string, 3: ?string} [score, vector, version, severity]
     */
    private function extractCvss(array $rawPayload): array
    {
        $best = null;

        foreach ($this->vectorCandidates($rawPayload) as $candidate) {
            $parsed = $this->withoutNoImpactScore(Cvss::fromVector($candidate));

            if ($parsed !== null && ($best === null || $this->outranks($parsed, $best))) {
                $best = $parsed;
            }
        }

        if ($best !== null) {
            return [
                $best->baseScore,
                $best->vector,
                $best->version,
                $best->baseSeverity ?? $this->qualitativeSeverity($rawPayload),
            ];
        }

        return [null, null, null, $this->qualitativeSeverity($rawPayload)];
    }

    /**
     * A vector with no confidentiality, integrity or availability impact scores
     * 0.0, which GitHub publishes next to advisories it rates HIGH or LOW. It says
     * nothing about the advisory, so it is kept unscored and the qualitative label
     * (or another vector) decides the severity.
     */
    private function withoutNoImpactScore(?Cvss $cvss): ?Cvss
    {
        return $cvss !== null && $cvss->baseScore === 0.0
            ? new Cvss($cvss->version, $cvss->vector, null, null)
            : $cvss;
    }

    /**
     * @param  array<string, mixed>  $rawPayload
     * @return list<string>
     */
    private function vectorCandidates(array $rawPayload): array
    {
        $candidates = [];

        $harvest = function (array $node) use (&$candidates): void {
            foreach ($node['severity'] ?? [] as $entry) {
                if (is_array($entry) && isset($entry['score']) && is_string($entry['score'])) {
                    $candidates[] = $entry['score'];
                }
            }

            $vectorString = $node['database_specific']['cvss']['vector_string'] ?? null;

            if (is_string($vectorString)) {
                $candidates[] = $vectorString;
            }
        };

        $harvest($rawPayload);

        foreach ($rawPayload['affected'] ?? [] as $affected) {
            if (is_array($affected)) {
                $harvest($affected);
            }
        }

        return $candidates;
    }

    private function outranks(Cvss $candidate, Cvss $current): bool
    {
        $rank = fn (Cvss $c): array => [
            $c->baseScore !== null ? 1 : 0,
            (float) $c->version,
            $c->baseScore ?? -1.0,
        ];

        return ($rank($candidate) <=> $rank($current)) > 0;
    }

    /**
     * @param  array<string, mixed>  $rawPayload
     */
    private function qualitativeSeverity(array $rawPayload): ?string
    {
        $nodes = [$rawPayload];

        foreach ($rawPayload['affected'] ?? [] as $affected) {
            if (is_array($affected)) {
                $nodes[] = $affected;
            }
        }

        foreach ($nodes as $node) {
            foreach (['database_specific', 'ecosystem_specific'] as $key) {
                $label = $node[$key]['severity'] ?? null;

                if (is_string($label) && $label !== '' && strtolower($label) !== 'unknown') {
                    return Severity::label($label);
                }
            }
        }

        return null;
    }

    /**
     * @param  array<int, array<string, mixed>>  $references
     * @return array<int, array{url: string, tags: array<int, string>}>
     */
    private function extractReferences(array $references): array
    {
        return array_map(
            fn (array $ref) => ['url' => $ref['url'] ?? '', 'tags' => array_filter([$ref['type'] ?? null])],
            $references
        );
    }

    private function parseDate(?string $value): ?Carbon
    {
        return $value !== null ? Carbon::parse($value) : null;
    }

    /**
     * @param  array<string, mixed>  $rawPayload
     */
    private function extractDescription(array $rawPayload): ?string
    {
        return $this->normalizeDescription($rawPayload['details'] ?? null)
            ?? $this->normalizeDescription($rawPayload['summary'] ?? null);
    }

    private function normalizeDescription(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $trimmed = trim($value);

        if ($trimmed === '' || preg_match('/^[A-Za-z][A-Za-z \'\/-]*:$/', $trimmed) === 1) {
            return null;
        }

        return $value;
    }
}
