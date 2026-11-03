<?php

use App\Mcp\Servers\RozhanitsyServer;
use App\Mcp\Tools\GetRemediation;
use App\Models\ParsedRecord;
use App\Models\VersionRange;
use Illuminate\Testing\Fluent\AssertableJson;

test('lists the fixed version of each affected package with the patch and advisory links', function () {
    $cve = ParsedRecord::factory()->create(['external_id' => 'CVE-2026-4000', 'references' => [
        ['url' => 'https://example.com/patch', 'tags' => ['Patch', 'Third Party Advisory']],
        ['url' => 'https://example.com/exploit', 'tags' => ['Exploit']],
    ]]);
    VersionRange::factory()->for($cve)->create(['vendor' => 'apache', 'product' => 'log4j', 'version_excl_end' => '2.17.1']);
    $advisory = ParsedRecord::factory()->create(['external_id' => 'GHSA-aaaa-bbbb-cccc', 'references' => [
        ['url' => 'https://example.com/patch', 'tags' => ['FIX']],
        ['url' => 'https://example.com/blog', 'tags' => ['WEB']],
    ]]);
    $advisory->aliases()->create(['alias' => 'CVE-2026-4000']);
    VersionRange::factory()->for($advisory)->create(['vendor' => null, 'ecosystem' => 'Maven', 'product' => 'org.apache.logging.log4j:log4j-core', 'version_incl_end' => '2.17.0', 'version_excl_end' => null]);

    RozhanitsyServer::tool(GetRemediation::class, ['id' => 'CVE-2026-4000'])
        ->assertOk()
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->where('id', 'CVE-2026-4000')
            ->has('fixes', 2)
            ->where('fixes.0.record_id', 'CVE-2026-4000')
            ->where('fixes.0.fixed_in', '2.17.1')
            ->where('fixes.0.affected_range.product', 'log4j')
            ->where('fixes.1.record_id', 'GHSA-aaaa-bbbb-cccc')
            ->where('fixes.1.fixed_in', null)
            ->where('references', [['url' => 'https://example.com/patch', 'tags' => ['Patch', 'Third Party Advisory']]]));
});

test('reports versionless ranges as low confidence and leaves out ranges that do not apply', function () {
    $record = ParsedRecord::factory()->create(['external_id' => 'CVE-2026-4001']);
    VersionRange::factory()->for($record)->create(['version_scope' => 'any', 'version_incl_start' => null, 'version_excl_end' => null]);
    VersionRange::factory()->for($record)->create(['version_scope' => 'na']);

    RozhanitsyServer::tool(GetRemediation::class, ['id' => 'CVE-2026-4001'])
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->has('fixes', 1)
            ->where('fixes.0.fixed_in', null)
            ->where('fixes.0.confidence', 'low')
            ->etc());
});

test('narrows fixes to one package', function (array $filter) {
    $record = ParsedRecord::factory()->create(['external_id' => 'CVE-2026-4002']);
    VersionRange::factory()->for($record)->create(['vendor' => 'apache', 'product' => 'log4j', 'ecosystem' => null]);
    VersionRange::factory()->for($record)->create(['vendor' => 'debian', 'product' => 'apache-log4j2', 'ecosystem' => 'Debian:12']);

    RozhanitsyServer::tool(GetRemediation::class, ['id' => 'CVE-2026-4002', ...$filter])
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->has('fixes', 1)
            ->where('fixes.0.affected_range.product', 'apache-log4j2')
            ->etc());
})->with([
    'vendor' => [['vendor' => 'debian']],
    'product' => [['product' => 'apache-log4j2']],
    'ecosystem' => [['ecosystem' => 'Debian:12']],
]);

test('offers no fixes for a withdrawn or rejected record', function (string $status) {
    $record = ParsedRecord::factory()->create(['external_id' => 'CVE-2026-4003', 'status' => $status, 'references' => [
        ['url' => 'https://example.com/patch', 'tags' => ['Patch']],
    ]]);
    VersionRange::factory()->for($record)->create();

    RozhanitsyServer::tool(GetRemediation::class, ['id' => 'CVE-2026-4003'])
        ->assertOk()
        ->assertStructuredContent(['id' => 'CVE-2026-4003', 'fixes' => [], 'references' => []]);
})->with(['withdrawn', 'Rejected']);

test('returns an error for an unknown id', function () {
    RozhanitsyServer::tool(GetRemediation::class, ['id' => 'CVE-1999-0001'])
        ->assertHasErrors(['No vulnerability found for [CVE-1999-0001].']);
});
