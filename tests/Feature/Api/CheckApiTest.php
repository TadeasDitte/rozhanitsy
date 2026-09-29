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
