<?php

use App\Ingestion\Parsers\NVDRecordParser;

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function nvdPayload(array $overrides = []): array
{
    return ['cve' => array_replace([
        'id' => 'CVE-2026-8376',
        'configurations' => [['nodes' => [['cpeMatch' => [['criteria' => 'cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*', 'vulnerable' => true]]]]]],
    ], $overrides)];
}

test('keeps the CNA affected entries after the CPE configurations', function () {
    $entry = ['packageName' => 'perl', 'versions' => [['version' => '0', 'lessThan' => '5.40.5-RC1', 'status' => 'affected']]];

    $parsed = (new NVDRecordParser)->parseOne(nvdPayload([
        'affected' => [['source' => 'cna-uuid', 'affectedData' => [$entry, ['packageName' => 'other']]]],
    ]));

    expect($parsed->rawRanges)->toHaveCount(2)
        ->and($parsed->rawRanges[1])->toBe(['cna' => [$entry, ['packageName' => 'other']]]);
});

test('keeps only the CPE configurations when the record has no affected entries', function () {
    $parsed = (new NVDRecordParser)->parseOne(nvdPayload());

    expect($parsed->rawRanges)->toHaveCount(1)
        ->and($parsed->rawRanges[0])->toHaveKey('nodes');
});

test('keeps the CNA entries of a record without CPE configurations', function () {
    $parsed = (new NVDRecordParser)->parseOne(nvdPayload([
        'configurations' => [],
        'affected' => [['source' => 'cna-uuid', 'affectedData' => [['packageName' => 'perl']]]],
    ]));

    expect($parsed->rawRanges)->toBe([['cna' => [['packageName' => 'perl']]]]);
});
