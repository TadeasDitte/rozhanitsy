<?php

use App\Models\Alias;
use App\Models\ParsedRecord;
use App\Models\VersionRange;

function wordpressRange(array $bounds, array $record = []): VersionRange
{
    return VersionRange::factory()
        ->for(ParsedRecord::factory()->state($record))
        ->create([
            'vendor' => 'wordpress',
            'product' => 'wordpress',
            'version_incl_start' => null,
            'version_excl_end' => null,
            ...$bounds,
        ]);
}

test('reports a vulnerable version with aliases and the fixing version', function () {
    $range = wordpressRange(['version_incl_start' => '6.9', 'version_excl_end' => '6.9.5'], [
        'external_id' => 'CVE-2026-1000',
        'cvss_score' => 9.8,
        'cvss_severity' => 'CRITICAL',
        'known_exploited' => true,
    ]);
    Alias::factory()->for($range->parsedRecord)->create(['alias' => 'GHSA-aaaa-bbbb-cccc']);

    $this->getJson(route('api.v1.check', ['vendor' => 'wordpress', 'product' => 'wordpress', 'version' => '6.9.2']))
        ->assertOk()
        ->assertJsonPath('data.vulnerable', true)
        ->assertJsonPath('data.vulnerability_count', 1)
        ->assertJsonPath('data.recommended_version', '6.9.5')
        ->assertJsonPath('data.vulnerabilities.0.id', 'CVE-2026-1000')
        ->assertJsonPath('data.vulnerabilities.0.aliases', ['GHSA-aaaa-bbbb-cccc'])
        ->assertJsonPath('data.vulnerabilities.0.fixed_in', '6.9.5')
        ->assertJsonPath('data.vulnerabilities.0.severity', 'CRITICAL')
        ->assertJsonPath('data.vulnerabilities.0.known_exploited', true)
        ->assertJsonPath('data.vulnerabilities.0.affected_range.version_incl_start', '6.9');
});

test('reports a version outside every range as not vulnerable', function () {
    wordpressRange(['version_incl_start' => '6.9', 'version_excl_end' => '6.9.5']);

    $this->getJson(route('api.v1.check', ['vendor' => 'wordpress', 'product' => 'wordpress', 'version' => '6.9.5']))
        ->assertOk()
        ->assertJsonPath('data.vulnerable', false)
        ->assertJsonPath('data.recommended_version', null)
        ->assertJsonPath('data.vulnerabilities', []);
});

test('recommends the highest fix across all matches', function () {
    wordpressRange(['version_excl_end' => '6.9.5']);
    wordpressRange(['version_excl_end' => '6.10.1']);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.9']))
        ->assertJsonPath('data.vulnerability_count', 2)
        ->assertJsonPath('data.recommended_version', '6.10.1');
});

test('recommends no version when a match has no known fix', function () {
    wordpressRange(['version_excl_end' => '6.9.5']);
    wordpressRange(['version_incl_end' => '7.0']);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.9']))
        ->assertJsonPath('data.vulnerability_count', 2)
        ->assertJsonPath('data.recommended_version', null);
});

test('lists a record once when several of its ranges match', function () {
    $range = wordpressRange(['version_excl_end' => '7.0']);
    VersionRange::factory()->for($range->parsedRecord)->create([
        'vendor' => 'wordpress', 'product' => 'wordpress', 'version_incl_start' => '6.0', 'version_excl_end' => '6.9.5',
    ]);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.5']))
        ->assertJsonPath('data.vulnerability_count', 1);
});

test('ignores withdrawn and rejected records', function (string $status) {
    wordpressRange(['version_excl_end' => '7.0'], ['status' => $status]);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.5']))
        ->assertJsonPath('data.vulnerable', false);
})->with(['withdrawn', 'Rejected']);

test('narrows matches by vendor and ecosystem', function (array $filter) {
    wordpressRange(['version_excl_end' => '7.0', 'ecosystem' => 'Packagist']);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.5', ...$filter]))
        ->assertJsonPath('data.vulnerable', false);
})->with([
    'other vendor' => [['vendor' => 'automattic']],
    'other ecosystem' => [['ecosystem' => 'npm']],
]);

test('requires product and version', function () {
    $this->getJson(route('api.v1.check'))
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['product', 'version']);
});

test('checks several packages in one batch', function () {
    wordpressRange(['version_excl_end' => '7.0']);

    $this->postJson(route('api.v1.check.batch'), ['packages' => [
        ['product' => 'wordpress', 'version' => '6.5'],
        ['product' => 'wordpress', 'version' => '7.0'],
    ]])
        ->assertOk()
        ->assertJsonCount(2, 'data')
        ->assertJsonPath('data.0.vulnerable', true)
        ->assertJsonPath('data.1.vulnerable', false);
});

test('rejects an invalid batch', function (array $payload, string $error) {
    $this->postJson(route('api.v1.check.batch'), $payload)
        ->assertUnprocessable()
        ->assertJsonValidationErrors([$error]);
})->with([
    'empty' => [['packages' => []], 'packages'],
    'too many' => [['packages' => array_fill(0, 101, ['product' => 'x', 'version' => '1'])], 'packages'],
    'missing version' => [['packages' => [['product' => 'x']]], 'packages.0.version'],
]);

test('never matches a range whose versions are not applicable', function () {
    wordpressRange(['version_scope' => 'na']);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.9', 'include_low_confidence' => 1]))
        ->assertJsonPath('data.vulnerable', false);
});

test('leaves out versionless ranges unless low confidence results are requested', function () {
    wordpressRange(['version_scope' => 'any'], ['external_id' => 'CVE-2007-2627']);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.9']))
        ->assertJsonPath('data.vulnerable', false);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.9', 'include_low_confidence' => 1]))
        ->assertJsonPath('data.vulnerable', true)
        ->assertJsonPath('data.vulnerabilities.0.id', 'CVE-2007-2627')
        ->assertJsonPath('data.vulnerabilities.0.confidence', 'low')
        ->assertJsonPath('data.vulnerabilities.0.affected_range.version_scope', 'any');
});

test('recommends a version from high confidence matches only', function () {
    wordpressRange(['version_excl_end' => '6.9.5']);
    wordpressRange(['version_scope' => 'any']);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.9', 'include_low_confidence' => 1]))
        ->assertJsonPath('data.vulnerability_count', 2)
        ->assertJsonPath('data.recommended_version', '6.9.5');
});

test('prefers the bounded range when a record also has a versionless one', function () {
    $range = wordpressRange(['version_scope' => 'any']);
    VersionRange::factory()->for($range->parsedRecord)->create([
        'vendor' => 'wordpress', 'product' => 'wordpress', 'version_incl_start' => null, 'version_excl_end' => '7.0',
    ]);

    $this->getJson(route('api.v1.check', ['product' => 'wordpress', 'version' => '6.9', 'include_low_confidence' => 1]))
        ->assertJsonPath('data.vulnerability_count', 1)
        ->assertJsonPath('data.vulnerabilities.0.confidence', 'high')
        ->assertJsonPath('data.vulnerabilities.0.fixed_in', '7.0');
});

test('applies the low confidence flag to a whole batch', function () {
    wordpressRange(['version_scope' => 'any']);

    $this->postJson(route('api.v1.check.batch'), [
        'include_low_confidence' => true,
        'packages' => [['product' => 'wordpress', 'version' => '6.9']],
    ])->assertJsonPath('data.0.vulnerable', true);
});

test('skips language runtime ranges unless a vendor names them', function () {
    VersionRange::factory()->create([
        'vendor' => 'ruby-lang', 'product' => 'zlib', 'plugs_into' => 'ruby',
        'version_incl_start' => null, 'version_excl_end' => '3.0.1',
    ]);

    $this->getJson(route('api.v1.check', ['product' => 'zlib', 'version' => '1.3.2']))
        ->assertJsonPath('data.vulnerable', false);
    $this->getJson(route('api.v1.check', ['vendor' => 'ruby-lang', 'product' => 'zlib', 'version' => '1.3.2']))
        ->assertJsonPath('data.vulnerability_count', 1);
});

test('keeps platform bound ranges that are not language runtimes', function () {
    VersionRange::factory()->create([
        'vendor' => 'automattic', 'product' => 'jetpack', 'plugs_into' => 'wordpress',
        'version_incl_start' => null, 'version_excl_end' => '12.0',
    ]);

    $this->getJson(route('api.v1.check', ['product' => 'jetpack', 'version' => '11.0']))
        ->assertJsonPath('data.vulnerable', true);
});

test('asks for a vendor or ecosystem when matches span several vendors', function () {
    foreach (['apache', 'other_vendor'] as $vendor) {
        VersionRange::factory()->create([
            'vendor' => $vendor, 'product' => 'orc', 'version_incl_start' => null, 'version_excl_end' => '2.0',
        ]);
    }
    $query = ['product' => 'orc', 'version' => '1.0'];

    $this->getJson(route('api.v1.check', $query))
        ->assertOk()
        ->assertJsonPath('data.ambiguous', true)
        ->assertJsonPath('data.vulnerable', null)
        ->assertJsonPath('data.vulnerability_count', 0)
        ->assertJsonPath('data.recommended_version', null)
        ->assertJsonPath('data.candidates', [
            ['vendor' => 'apache', 'ecosystem' => null],
            ['vendor' => 'other_vendor', 'ecosystem' => null],
        ]);
    $this->getJson(route('api.v1.check', [...$query, 'vendor' => 'apache']))
        ->assertJsonPath('data.ambiguous', false)
        ->assertJsonPath('data.vulnerability_count', 1);
});

test('treats the same package in NVD and OSV as one product', function () {
    VersionRange::factory()->create([
        'vendor' => 'lodash', 'ecosystem' => null, 'product' => 'lodash', 'version_incl_start' => null, 'version_excl_end' => '4.17.21',
    ]);
    VersionRange::factory()->create([
        'vendor' => null, 'ecosystem' => 'npm', 'product' => 'lodash', 'version_incl_start' => null, 'version_excl_end' => '4.17.21',
    ]);

    $this->getJson(route('api.v1.check', ['product' => 'lodash', 'version' => '4.17.20']))
        ->assertJsonPath('data.ambiguous', false)
        ->assertJsonPath('data.vulnerability_count', 2);
});

test('flags only the ambiguous package in a batch', function () {
    foreach (['apache', 'other_vendor'] as $vendor) {
        VersionRange::factory()->create([
            'vendor' => $vendor, 'product' => 'orc', 'version_incl_start' => null, 'version_excl_end' => '2.0',
        ]);
    }

    $this->postJson(route('api.v1.check.batch'), ['packages' => [
        ['product' => 'orc', 'version' => '1.0'],
        ['product' => 'zlib', 'version' => '1.3.2'],
    ]])
        ->assertOk()
        ->assertJsonPath('data.0.ambiguous', true)
        ->assertJsonPath('data.1.ambiguous', false)
        ->assertJsonPath('data.1.vulnerable', false);
});

test('takes the skipped language runtimes from config', function () {
    config(['matching.language_runtimes' => ['wordpress']]);
    foreach ([['ruby-lang', 'ruby'], ['automattic', 'wordpress']] as [$vendor, $platform]) {
        VersionRange::factory()->create([
            'vendor' => $vendor, 'product' => 'widget', 'plugs_into' => $platform,
            'version_incl_start' => null, 'version_excl_end' => '2.0',
        ]);
    }

    $this->getJson(route('api.v1.check', ['product' => 'widget', 'version' => '1.0']))
        ->assertJsonPath('data.vulnerability_count', 1)
        ->assertJsonPath('data.vulnerabilities.0.affected_range.vendor', 'ruby-lang');
});

test('searches only NVD and language ecosystems unless an ecosystem is given', function () {
    $ranges = [
        ['vendor' => 'openssl', 'ecosystem' => null],
        ['vendor' => null, 'ecosystem' => 'npm'],
        ['vendor' => 'debian', 'ecosystem' => 'Debian:12'],
    ];
    foreach ($ranges as $range) {
        VersionRange::factory()->create([
            ...$range, 'product' => 'openssl', 'version_incl_start' => null, 'version_excl_end' => '4.0',
        ]);
    }
    $query = ['product' => 'openssl', 'version' => '3.0.7'];

    $this->getJson(route('api.v1.check', $query))
        ->assertJsonPath('data.ambiguous', false)
        ->assertJsonPath('data.vulnerability_count', 2);
    $this->getJson(route('api.v1.check', [...$query, 'ecosystem' => 'Debian:12']))
        ->assertJsonPath('data.vulnerability_count', 1)
        ->assertJsonPath('data.vulnerabilities.0.affected_range.vendor', 'debian');
});

test('ignores distro vendors and ecosystems when judging ambiguity', function () {
    foreach (['Debian:12', 'Ubuntu:24.04:LTS', 'Alpine:v3.17'] as $ecosystem) {
        VersionRange::factory()->create([
            'vendor' => strtolower(strtok($ecosystem, ':')), 'ecosystem' => $ecosystem, 'product' => 'zlib',
            'version_incl_start' => null, 'version_excl_end' => '2.0',
        ]);
    }

    $this->getJson(route('api.v1.check', ['product' => 'zlib', 'version' => '1.3.2']))
        ->assertJsonPath('data.ambiguous', false)
        ->assertJsonPath('data.vulnerable', false);
});

test('asks for an ecosystem when a name exists in several language ecosystems', function () {
    foreach (['npm', 'PyPI'] as $ecosystem) {
        VersionRange::factory()->create([
            'vendor' => null, 'ecosystem' => $ecosystem, 'product' => 'requests',
            'version_incl_start' => null, 'version_excl_end' => '2.0',
        ]);
    }

    $this->getJson(route('api.v1.check', ['product' => 'requests', 'version' => '1.0']))
        ->assertJsonPath('data.ambiguous', true)
        ->assertJsonPath('data.candidates', [
            ['vendor' => null, 'ecosystem' => 'PyPI'],
            ['vendor' => null, 'ecosystem' => 'npm'],
        ]);
});
