<?php

use App\Mcp\Servers\RozhanitsyServer;
use App\Mcp\Tools\RecentChanges;
use App\Models\ParsedRecord;
use App\Models\VersionRange;
use Illuminate\Testing\Fluent\AssertableJson;

beforeEach(function () {
    $this->travelTo('2026-11-03 12:00:00');
});

function recentRecord(array $record = [], array $range = []): ParsedRecord
{
    return VersionRange::factory()
        ->for(ParsedRecord::factory()->state(['published_at' => '2026-01-01', 'last_modified_at' => '2026-11-02', ...$record]))
        ->create($range)
        ->parsedRecord;
}

test('lists records changed since the date, most recently modified first, telling new from updated', function () {
    recentRecord(['external_id' => 'CVE-2026-0001', 'published_at' => '2026-10-31', 'last_modified_at' => '2026-11-01']);
    recentRecord(['external_id' => 'CVE-2020-0002', 'published_at' => '2020-01-01', 'last_modified_at' => '2026-11-02']);
    recentRecord(['external_id' => 'CVE-2026-0003', 'last_modified_at' => '2026-10-29']);

    RozhanitsyServer::tool(RecentChanges::class, ['since' => '2026-10-30'])
        ->assertOk()
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->where('since', '2026-10-30T00:00:00+00:00')
            ->where('has_more', false)
            ->has('vulnerabilities', 2)
            ->where('vulnerabilities.0.id', 'CVE-2020-0002')
            ->where('vulnerabilities.0.change', 'modified')
            ->where('vulnerabilities.1.id', 'CVE-2026-0001')
            ->where('vulnerabilities.1.change', 'published'));
});

test('looks back 7 days by default', function () {
    recentRecord(['external_id' => 'CVE-2026-0001', 'last_modified_at' => '2026-10-27 13:00:00']);
    recentRecord(['external_id' => 'CVE-2026-0002', 'last_modified_at' => '2026-10-27 11:00:00']);

    RozhanitsyServer::tool(RecentChanges::class)
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->has('vulnerabilities', 1)
            ->where('vulnerabilities.0.id', 'CVE-2026-0001')
            ->etc());
});

test('narrows the list by package, severity and exploitation', function (array $filter, array $matching, array $other) {
    $expected = recentRecord(...$matching);
    recentRecord(...$other);

    RozhanitsyServer::tool(RecentChanges::class, $filter)
        ->assertOk()
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->has('vulnerabilities', 1)
            ->where('vulnerabilities.0.id', $expected->external_id)
            ->etc());
})->with([
    'vendor' => [['vendor' => 'nginx'], ['range' => ['vendor' => 'nginx']], ['range' => ['vendor' => 'f5']]],
    'product' => [['product' => 'nginx'], ['range' => ['product' => 'nginx']], ['range' => ['product' => 'httpd']]],
    'ecosystem' => [['ecosystem' => 'npm'], ['range' => ['ecosystem' => 'npm']], ['range' => ['ecosystem' => 'PyPI']]],
    'severity however the source capitalises it' => [['severity' => 'CRITICAL'], ['record' => ['cvss_severity' => 'Critical']], ['record' => ['cvss_severity' => 'HIGH']]],
    'the moderate severity of GitHub advisories' => [['severity' => 'MODERATE'], ['record' => ['cvss_severity' => 'Medium']], ['record' => ['cvss_severity' => 'HIGH']]],
    'known exploited' => [['known_exploited' => true], ['record' => ['known_exploited' => true]], ['record' => ['known_exploited' => false]]],
    'not known exploited' => [['known_exploited' => false], ['record' => ['known_exploited' => false]], ['record' => ['known_exploited' => true]]],
]);

test('leaves out withdrawn and rejected records', function (string $status) {
    recentRecord(['status' => $status]);

    RozhanitsyServer::tool(RecentChanges::class)
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->where('vulnerabilities', [])
            ->etc());
})->with(['withdrawn', 'Rejected']);

test('cuts the list at the limit and says when more changed', function (int $limit, int $listed, bool $hasMore) {
    recentRecord();
    recentRecord();
    recentRecord();

    RozhanitsyServer::tool(RecentChanges::class, ['limit' => $limit])
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->has('vulnerabilities', $listed)
            ->where('has_more', $hasMore)
            ->etc());
})->with([
    'below the count' => [2, 2, true],
    'at the count' => [3, 3, false],
]);

test('rejects an invalid date, severity or limit', function (array $arguments, string $error) {
    RozhanitsyServer::tool(RecentChanges::class, $arguments)
        ->assertHasErrors([$error]);
})->with([
    'invalid date' => [['since' => 'last tuesday-ish'], 'The since field must be a valid date.'],
    'unknown severity' => [['severity' => 'SPICY'], 'The selected severity is invalid.'],
    'limit above 100' => [['limit' => 101], 'The limit field must not be greater than 100.'],
]);
