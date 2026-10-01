<?php

namespace App\Ingestion;

use Carbon\Carbon;

final readonly class ParsedRecordData
{
    /**
     * @param  array<int, string>  $aliases
     * @param  array<int, string>  $weaknesses
     * @param  array<int, array{url: string, tags: array<int, string>}>  $references
     * @param  array<int, array<string, mixed>>  $rawRanges
     */
    public function __construct(
        public string $externalId,
        public array $aliases,
        public ?float $cvssScore,
        public ?string $cvssVector,
        public ?string $cvssVersion,
        public ?string $cvssSeverity,
        public ?string $description,
        public ?Carbon $publishedAt,
        public ?Carbon $lastModifiedAt,
        public array $weaknesses,
        public array $references,
        public ?string $status,
        public bool $knownExploited,
        public array $rawRanges,
    ) {}
}
