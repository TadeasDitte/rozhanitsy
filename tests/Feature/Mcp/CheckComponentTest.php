<?php

use App\Mcp\Servers\RozhanitsyServer;
use App\Mcp\Tools\CheckComponent;
use App\Models\ParsedRecord;
use App\Models\VersionRange;
use Illuminate\Testing\Fluent\AssertableJson;

function wordpressPluginRange(array $range = [], array $record = []): VersionRange
{
    return VersionRange::factory()
        ->for(ParsedRecord::factory()->state(['cvss_score' => 9.8, 'cvss_severity' => 'CRITICAL', ...$record]))
        ->create([
            'vendor' => 'wordpress',
            'product' => 'wordpress',
            'ecosystem' => 'Packagist',
            'version_incl_start' => '6.9',
            'version_excl_end' => '6.9.5',
            ...$range,
        ]);
}

test('reports a vulnerable version with the fixing version', function () {
    wordpressPluginRange(record: ['external_id' => 'CVE-2026-1000']);

    RozhanitsyServer::tool(CheckComponent::class, ['product' => 'wordpress', 'version' => '6.9.2'])
        ->assertOk()
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->where('vulnerable', true)
            ->where('vulnerability_count', 1)
            ->where('recommended_version', '6.9.5')
            ->where('vulnerabilities.0.id', 'CVE-2026-1000')
            ->etc());
});

test('narrows matches by vendor, ecosystem, severity and minimum score', function (array $filter) {
    wordpressPluginRange();

    RozhanitsyServer::tool(CheckComponent::class, ['product' => 'wordpress', 'version' => '6.9.2', ...$filter])
        ->assertOk()
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->where('vulnerable', false)
            ->etc());
})->with([
    'other vendor' => [['vendor' => 'automattic']],
    'other ecosystem' => [['ecosystem' => 'npm']],
    'other severity' => [['severity' => 'LOW']],
    'higher minimum score' => [['min_score' => 9.9]],
]);

test('leaves out versionless ranges unless low confidence results are requested', function () {
    wordpressPluginRange(['version_scope' => 'any']);

    RozhanitsyServer::tool(CheckComponent::class, ['product' => 'wordpress', 'version' => '6.9.2'])
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->where('vulnerable', false)
            ->etc());

    RozhanitsyServer::tool(CheckComponent::class, ['product' => 'wordpress', 'version' => '6.9.2', 'include_low_confidence' => true])
        ->assertStructuredContent(fn (AssertableJson $json) => $json
            ->where('vulnerable', true)
            ->where('vulnerabilities.0.confidence', 'low')
            ->etc());
});

test('requires product and version', function () {
    RozhanitsyServer::tool(CheckComponent::class)
        ->assertHasErrors(['The product field is required.', 'The version field is required.']);
});

test('rejects an unknown severity or a minimum score outside 0 to 10', function (array $filter, string $error) {
    RozhanitsyServer::tool(CheckComponent::class, ['product' => 'wordpress', 'version' => '6.9.2', ...$filter])
        ->assertHasErrors([$error]);
})->with([
    'unknown severity' => [['severity' => 'SPICY'], 'The selected severity is invalid.'],
    'score above 10' => [['min_score' => 10.1], 'The min score field must be between 0 and 10.'],
]);
