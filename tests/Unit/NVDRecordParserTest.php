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
        ->and($parsed->rawRanges[1])->toBe(['cna' => [[...$entry, 'source' => 'cna-uuid'], ['packageName' => 'other', 'source' => 'cna-uuid']]]);
});

test('tags each affected entry with the container it comes from', function () {
    $parsed = (new NVDRecordParser)->parseOne(nvdPayload([
        'affected' => [
            ['source' => 'cna-uuid', 'affectedData' => [['packageName' => 'perl']]],
            ['source' => 'adp-uuid', 'affectedData' => [['packageName' => 'perl']]],
        ],
    ]));

    expect(array_column($parsed->rawRanges[1]['cna'], 'source'))->toBe(['cna-uuid', 'adp-uuid']);
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

    expect($parsed->rawRanges)->toBe([['cna' => [['packageName' => 'perl', 'source' => 'cna-uuid']]]]);
});

/**
 * @return array<int, array<string, mixed>>
 */
function nvdCvssMetric(string $version, float $score, string $severity, string $vector): array
{
    return [['cvssData' => ['version' => $version, 'vectorString' => $vector, 'baseScore' => $score, 'baseSeverity' => $severity]]];
}

test('scores a record from the best CVSS metric NVD holds for it', function (array $metrics, array $expected) {
    $parsed = (new NVDRecordParser)->parseOne(nvdPayload(['metrics' => $metrics]));

    expect([$parsed->cvssScore, $parsed->cvssVersion, $parsed->cvssSeverity])->toBe($expected);
})->with([
    'only a v4.0 metric' => [
        ['cvssMetricV40' => nvdCvssMetric('4.0', 8.7, 'HIGH', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N')],
        [8.7, '4.0', 'HIGH'],
    ],
    'its own v3.1 analysis next to a v4.0 metric' => [
        [
            'cvssMetricV31' => nvdCvssMetric('3.1', 7.5, 'HIGH', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N'),
            'cvssMetricV40' => nvdCvssMetric('4.0', 8.7, 'HIGH', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N'),
        ],
        [7.5, '3.1', 'HIGH'],
    ],
    'a v4.0 metric next to a v2.0 one' => [
        [
            'cvssMetricV2' => [['baseSeverity' => 'MEDIUM', 'cvssData' => ['version' => '2.0', 'vectorString' => 'AV:N/AC:L/Au:N/C:N/I:P/A:N', 'baseScore' => 5.0]]],
            'cvssMetricV40' => nvdCvssMetric('4.0', 8.7, 'HIGH', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N'),
        ],
        [8.7, '4.0', 'HIGH'],
    ],
    'a v2.0 metric, whose severity NVD puts beside the data' => [
        ['cvssMetricV2' => [['baseSeverity' => 'MEDIUM', 'cvssData' => ['version' => '2.0', 'vectorString' => 'AV:N/AC:L/Au:N/C:N/I:P/A:N', 'baseScore' => 5.0]]]],
        [5.0, '2.0', 'MEDIUM'],
    ],
    'no metric at all' => [[], [null, null, null]],
]);
