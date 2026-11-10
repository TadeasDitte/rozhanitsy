<?php

use App\Ingestion\Parsers\OSVRecordParser;

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function osvPayload(array $overrides = []): array
{
    return array_replace([
        'id' => 'GHSA-xxxx-yyyy-zzzz',
        'summary' => 'Example advisory',
        'affected' => [],
    ], $overrides);
}

test('reads a CVSS vector from the top-level severity block and scores it', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'severity' => [
            ['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
        ],
    ]));

    expect($parsed->cvssScore)->toBe(9.8);
    expect($parsed->cvssVector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect($parsed->cvssVersion)->toBe('3.1');
    expect($parsed->cvssSeverity)->toBe('Critical');
});

test('reads a CVSS vector that only appears inside an affected entry', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'affected' => [
            [
                'package' => ['ecosystem' => 'PyPI', 'name' => 'demo'],
                'severity' => [
                    ['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'],
                ],
            ],
        ],
    ]));

    expect($parsed->cvssScore)->toBe(7.5);
    expect($parsed->cvssVersion)->toBe('3.1');
    expect($parsed->cvssSeverity)->toBe('High');
});

test('prefers the higher CVSS version when several are present', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'severity' => [
            ['type' => 'CVSS_V2', 'score' => 'AV:N/AC:L/Au:N/C:P/I:P/A:P'],
            ['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
        ],
    ]));

    expect($parsed->cvssVersion)->toBe('3.1');
    expect($parsed->cvssScore)->toBe(9.8);
});

test('falls back to a qualitative database_specific severity when there is no vector', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'database_specific' => ['severity' => 'HIGH'],
    ]));

    expect($parsed->cvssScore)->toBeNull();
    expect($parsed->cvssVector)->toBeNull();
    expect($parsed->cvssVersion)->toBeNull();
    expect($parsed->cvssSeverity)->toBe('High');
});

test('falls back to a qualitative severity nested in an affected entry', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'affected' => [
            ['package' => ['ecosystem' => 'npm', 'name' => 'demo'], 'database_specific' => ['severity' => 'MODERATE']],
        ],
    ]));

    expect($parsed->cvssSeverity)->toBe('Medium');
});

test('does not score a CVSS v3 vector with no impact and takes the severity from the label', function (array $severity, string $label, string $expectedVersion, string $expectedSeverity) {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'severity' => $severity,
        'database_specific' => ['severity' => $label],
    ]));

    expect($parsed->cvssScore)->toBeNull();
    expect($parsed->cvssVersion)->toBe($expectedVersion);
    expect($parsed->cvssSeverity)->toBe($expectedSeverity);
})->with([
    'next to a v4 vector' => [
        [
            ['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'],
            ['type' => 'CVSS_V4', 'score' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N'],
        ],
        'HIGH', '4.0', 'High',
    ],
    'alone' => [
        [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N']],
        'LOW', '3.1', 'Low',
    ],
]);

test('ignores an unknown qualitative severity', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'database_specific' => ['severity' => 'Unknown'],
    ]));

    expect($parsed->cvssSeverity)->toBeNull();
});

test('keeps a v4.0 vector and version even though it cannot be scored', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'severity' => [
            ['type' => 'CVSS_V4', 'score' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
        ],
        'database_specific' => ['severity' => 'CRITICAL'],
    ]));

    expect($parsed->cvssVersion)->toBe('4.0');
    expect($parsed->cvssScore)->toBeNull();
    expect($parsed->cvssSeverity)->toBe('Critical');
});

test('leaves all CVSS fields null when nothing carries severity data', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload());

    expect($parsed->cvssScore)->toBeNull();
    expect($parsed->cvssVector)->toBeNull();
    expect($parsed->cvssVersion)->toBeNull();
    expect($parsed->cvssSeverity)->toBeNull();
});

test('still parses the non-severity fields', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'id' => 'GHSA-abcd-efgh-ijkl',
        'details' => 'Full details here',
        'aliases' => ['CVE-2026-1'],
    ]));

    expect($parsed->externalId)->toBe('GHSA-abcd-efgh-ijkl');
    expect($parsed->description)->toBe('Full details here');
    expect($parsed->aliases)->toBe(['CVE-2026-1']);
});

test('treats a bare section-label details value as no description', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'details' => 'Summary:',
        'summary' => null,
    ]));

    expect($parsed->description)->toBeNull();
});

test('falls back to summary when details is a bare label', function () {
    $parsed = (new OSVRecordParser)->parseOne(osvPayload([
        'details' => 'Summary:',
        'summary' => 'Real summary text',
    ]));

    expect($parsed->description)->toBe('Real summary text');
});
