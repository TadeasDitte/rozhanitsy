<?php

namespace App\Ingestion\Parsers;

use App\Ingestion\ParsedRecordData;
use Carbon\Carbon;

final class NVDRecordParser implements SourceRecordParser
{
    public function parseOne(array $rawPayload): ?ParsedRecordData
    {
        $cve = $rawPayload['cve'] ?? $rawPayload;

        if (empty($cve['id'])) {
            return null;
        }

        [$score, $vector, $version, $severity] = $this->extractCvss($cve['metrics'] ?? []);

        return new ParsedRecordData(
            externalId: $cve['id'],
            aliases: [],
            cvssScore: $score,
            cvssVector: $vector,
            cvssVersion: $version,
            cvssSeverity: $severity,
            description: $this->extractEnglishDescription($cve['descriptions'] ?? []),
            publishedAt: $this->parseDate($cve['published'] ?? null),
            lastModifiedAt: $this->parseDate($cve['lastModified'] ?? null),
            weaknesses: $this->extractWeaknesses($cve['weaknesses'] ?? []),
            references: $this->extractReferences($cve['references'] ?? []),
            status: $cve['vulnStatus'] ?? null,
            knownExploited: isset($cve['cisaExploitAdd']),
            rawRanges: $cve['configurations'] ?? [],
        );
    }

    /**
     * @param  array<string, mixed>  $metrics
     * @return array{?float, ?string, ?string, ?string}
     */
    private function extractCvss(array $metrics): array
    {
        foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $key) {
            $metric = $metrics[$key][0]['cvssData'] ?? null;

            if ($metric !== null) {
                return [
                    isset($metric['baseScore']) ? (float) $metric['baseScore'] : null,
                    $metric['vectorString'] ?? null,
                    $metric['version'] ?? null,
                    $metric['baseSeverity'] ?? $metrics[$key][0]['baseSeverity'] ?? null,
                ];
            }
        }

        return [null, null, null, null];
    }

    /**
     * @param  array<int, array<string, mixed>>  $descriptions
     */
    private function extractEnglishDescription(array $descriptions): ?string
    {
        foreach ($descriptions as $description) {
            if (($description['lang'] ?? null) === 'en') {
                return $description['value'] ?? null;
            }
        }

        return null;
    }

    /**
     * @param  array<int, array<string, mixed>>  $weaknesses
     * @return array<int, string>
     */
    private function extractWeaknesses(array $weaknesses): array
    {
        $cweIds = [];

        foreach ($weaknesses as $weakness) {
            foreach ($weakness['description'] ?? [] as $description) {
                if (($description['lang'] ?? null) === 'en' && ! empty($description['value'])) {
                    $cweIds[] = $description['value'];
                }
            }
        }

        return array_values(array_unique($cweIds));
    }

    /**
     * @param  array<int, array<string, mixed>>  $references
     * @return array<int, array{url: string, tags: array<int, string>}>
     */
    private function extractReferences(array $references): array
    {
        return array_map(
            fn (array $ref) => ['url' => $ref['url'] ?? '', 'tags' => $ref['tags'] ?? []],
            $references
        );
    }

    private function parseDate(?string $value): ?Carbon
    {
        return $value !== null ? Carbon::parse($value) : null;
    }
}
