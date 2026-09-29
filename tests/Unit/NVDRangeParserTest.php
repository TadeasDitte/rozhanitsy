<?php

use App\Ingestion\Parsers\NVDRangeParser;

/**
 * @param  list<array<string, mixed>>  $cpeMatch
 * @return list<array<string, mixed>>
 */
function nvdConfig(array $cpeMatch, ?string $operator = null): array
{
    $node = ['negate' => false, 'cpeMatch' => $cpeMatch];

    if ($operator !== null) {
        $node['operator'] = $operator;
    }

    return [['nodes' => [$node]]];
}

test('maps the four version qualifiers onto the range boundary columns', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        [
            'criteria' => 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',
            'vulnerable' => true,
            'versionStartIncluding' => '6.9',
            'versionEndExcluding' => '6.9.5',
        ],
    ]));

    expect($ranges)->toHaveCount(1);
    expect($ranges[0]->type)->toBe('a');
    expect($ranges[0]->vendor)->toBe('wordpress');
    expect($ranges[0]->product)->toBe('wordpress');
    expect($ranges[0]->versionInclStart)->toBe('6.9');
    expect($ranges[0]->versionExclStart)->toBeNull();
    expect($ranges[0]->versionInclEnd)->toBeNull();
    expect($ranges[0]->versionExclEnd)->toBe('6.9.5');
    expect($ranges[0]->raw)->toBe('cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*');
});

test('maps start-excluding and end-including qualifiers', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        [
            'criteria' => 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
            'vulnerable' => true,
            'versionStartExcluding' => '1.0',
            'versionEndIncluding' => '2.0',
        ],
    ]));

    expect($ranges[0]->versionExclStart)->toBe('1.0');
    expect($ranges[0]->versionInclEnd)->toBe('2.0');
    expect($ranges[0]->versionInclStart)->toBeNull();
    expect($ranges[0]->versionExclEnd)->toBeNull();
});

test('treats a concrete cpe version with no qualifiers as an exact match', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        [
            'criteria' => 'cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*',
            'vulnerable' => true,
        ],
    ]));

    expect($ranges[0]->versionInclStart)->toBe('1.2.3');
    expect($ranges[0]->versionInclEnd)->toBe('1.2.3');
    expect($ranges[0]->versionExclStart)->toBeNull();
    expect($ranges[0]->versionExclEnd)->toBeNull();
});

test('leaves every boundary null when the cpe version is a wildcard and no qualifiers are set', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        [
            'criteria' => 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
            'vulnerable' => true,
        ],
    ]));

    expect($ranges[0]->versionInclStart)->toBeNull();
    expect($ranges[0]->versionExclStart)->toBeNull();
    expect($ranges[0]->versionInclEnd)->toBeNull();
    expect($ranges[0]->versionExclEnd)->toBeNull();
});

test('normalizes the wildcard and NA markers to null for vendor and product', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        [
            'criteria' => 'cpe:2.3:a:*:-:1.0:*:*:*:*:*:*:*',
            'vulnerable' => true,
        ],
    ]));

    expect($ranges[0]->vendor)->toBeNull();
    expect($ranges[0]->product)->toBeNull();
});

test('maps the cpe part onto the type column', function (string $part, string $type) {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        [
            'criteria' => "cpe:2.3:{$part}:vendor:product:1.0:*:*:*:*:*:*:*",
            'vulnerable' => true,
        ],
    ]));

    expect($ranges[0]->type)->toBe($type);
})->with([
    'application' => ['a', 'a'],
    'operating system' => ['o', 'o'],
    'hardware' => ['h', 'h'],
    'wildcard part' => ['*', 'u'],
]);

test('ignores cpe matches that are not vulnerable', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        ['criteria' => 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*', 'vulnerable' => false],
        ['criteria' => 'cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*', 'vulnerable' => true],
    ]));

    expect($ranges)->toHaveCount(1);
    expect($ranges[0]->product)->toBe('other');
});

test('derives plugs_into from the non-vulnerable sibling of an AND node', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        [
            'criteria' => 'cpe:2.3:a:acme:acme_plugin:*:*:*:*:*:*:*:*',
            'vulnerable' => true,
            'versionEndExcluding' => '3.0',
        ],
        ['criteria' => 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*', 'vulnerable' => false],
    ], operator: 'AND'));

    expect($ranges)->toHaveCount(1);
    expect($ranges[0]->product)->toBe('acme_plugin');
    expect($ranges[0]->plugsInto)->toBe('wordpress');
});

test('flattens cpe matches across multiple nodes and configurations', function () {
    $ranges = (new NVDRangeParser)->parse([
        ['nodes' => [
            ['cpeMatch' => [['criteria' => 'cpe:2.3:a:v:a:1.0:*:*:*:*:*:*:*', 'vulnerable' => true]]],
            ['cpeMatch' => [['criteria' => 'cpe:2.3:a:v:b:1.0:*:*:*:*:*:*:*', 'vulnerable' => true]]],
        ]],
        ['nodes' => [
            ['cpeMatch' => [['criteria' => 'cpe:2.3:a:v:c:1.0:*:*:*:*:*:*:*', 'vulnerable' => true]]],
        ]],
    ]);

    expect(array_map(fn ($r) => $r->product, $ranges))->toBe(['a', 'b', 'c']);
});

test('returns an empty list when there are no configurations', function () {
    expect((new NVDRangeParser)->parse([]))->toBe([]);
});

test('throws on an unparseable cpe criteria string so the runner records it', function () {
    (new NVDRangeParser)->parse(nvdConfig([
        ['criteria' => 'not-a-cpe-string', 'vulnerable' => true],
    ]));
})->throws(InvalidArgumentException::class);

test('marks a range as any when the cpe version is a wildcard without qualifiers', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        ['criteria' => 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*', 'vulnerable' => true],
    ]));

    expect($ranges[0]->versionScope)->toBe('any');
});

test('marks a range as na when the cpe version is not applicable', function () {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([
        ['criteria' => 'cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*', 'vulnerable' => true],
    ]));

    expect($ranges[0]->versionScope)->toBe('na')
        ->and($ranges[0]->versionInclStart)->toBeNull()
        ->and($ranges[0]->versionInclEnd)->toBeNull();
});

test('marks bounded and exact ranges as range', function (array $match) {
    $ranges = (new NVDRangeParser)->parse(nvdConfig([['vulnerable' => true, ...$match]]));

    expect($ranges[0]->versionScope)->toBe('range');
})->with([
    'exact version' => [['criteria' => 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*']],
    'wildcard with qualifier' => [['criteria' => 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*', 'versionEndExcluding' => '2.0']],
    'na with qualifier' => [['criteria' => 'cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*', 'versionEndExcluding' => '2.0']],
]);

/**
 * @param  list<list<array<string, mixed>>>  $nodes  cpeMatch lists, one per node
 * @return list<array<string, mixed>>
 */
function nvdAndConfig(array $nodes): array
{
    return [[
        'operator' => 'AND',
        'nodes' => array_map(fn (array $cpeMatch): array => ['operator' => 'OR', 'negate' => false, 'cpeMatch' => $cpeMatch], $nodes),
    ]];
}

test('uses the non-vulnerable node of an AND configuration as plugs_into', function () {
    $ranges = (new NVDRangeParser)->parse(nvdAndConfig([
        [['criteria' => 'cpe:2.3:o:sun:sunos:4.1.4:*:*:*:*:*:*:*', 'vulnerable' => false]],
        [['criteria' => 'cpe:2.3:a:sendmail:sendmail:5:*:*:*:*:*:*:*', 'vulnerable' => true]],
    ]));

    expect($ranges)->toHaveCount(1)
        ->and($ranges[0]->product)->toBe('sendmail')
        ->and($ranges[0]->plugsInto)->toBe('sunos');
});

test('treats a versionless vulnerable node beside a versioned one as the platform', function () {
    $ranges = (new NVDRangeParser)->parse(nvdAndConfig([
        [
            ['criteria' => 'cpe:2.3:a:mark_jaquith:bad_behavior:*:*:*:*:*:*:*:*', 'vulnerable' => true, 'versionEndIncluding' => '2.0.46'],
            ['criteria' => 'cpe:2.3:a:mark_jaquith:bad_behavior:2.2.0:*:*:*:*:*:*:*', 'vulnerable' => true],
        ],
        [['criteria' => 'cpe:2.3:a:wordpress:wordpress:-:*:*:*:*:*:*:*', 'vulnerable' => true]],
    ]));

    expect(array_map(fn ($range) => [$range->product, $range->plugsInto], $ranges))->toBe([
        ['bad_behavior', 'wordpress'],
        ['bad_behavior', 'wordpress'],
    ]);
});

test('emits every node of an AND configuration when all of them are versioned', function () {
    $ranges = (new NVDRangeParser)->parse(nvdAndConfig([
        [['criteria' => 'cpe:2.3:a:adobe:flash_player:*:*:*:*:*:*:*:*', 'vulnerable' => true, 'versionEndExcluding' => '11.2.202.229']],
        [['criteria' => 'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*', 'vulnerable' => true, 'versionEndExcluding' => '18.0.1025.151']],
    ]));

    expect(array_map(fn ($range) => [$range->product, $range->plugsInto], $ranges))->toBe([
        ['flash_player', null],
        ['chrome', null],
    ]);
});

test('emits every node of an AND configuration when none of them are versioned', function () {
    $ranges = (new NVDRangeParser)->parse(nvdAndConfig([
        [['criteria' => 'cpe:2.3:a:acme:plugin:*:*:*:*:*:*:*:*', 'vulnerable' => true]],
        [['criteria' => 'cpe:2.3:a:wordpress:wordpress:-:*:*:*:*:*:*:*', 'vulnerable' => true]],
    ]));

    expect(array_map(fn ($range) => [$range->product, $range->versionScope], $ranges))->toBe([
        ['plugin', 'any'],
        ['wordpress', 'na'],
    ]);
});
