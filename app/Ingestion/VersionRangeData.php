<?php

namespace App\Ingestion;

final readonly class VersionRangeData
{
    /**
     * @param  'a'|'h'|'o'|'u'  $type  CPE part: application / hardware / os / unknown
     * @param  'range'|'any'|'na'  $versionScope  range: the bounds are authoritative (all null = every version);
     *                                            any: source gave no versions (CPE `*`), low confidence;
     *                                            na: versions not applicable (CPE `-`), never matches a version
     */
    public function __construct(
        public string $type,
        public ?string $ecosystem,
        public ?string $packageManager,
        public ?string $vendor,
        public ?string $product,
        public ?string $versionInclStart,
        public ?string $versionExclStart,
        public ?string $versionInclEnd,
        public ?string $versionExclEnd,
        public ?string $plugsInto,
        public ?string $raw,
        public string $versionScope = 'range',
    ) {}
}
