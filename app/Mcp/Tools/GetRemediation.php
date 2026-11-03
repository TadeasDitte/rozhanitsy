<?php

namespace App\Mcp\Tools;

use App\Http\Resources\V1\VersionRangeResource;
use App\Models\ParsedRecord;
use App\Models\VersionRange;
use App\Services\VulnerabilityLookup;
use App\Services\VulnerabilityMatch;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\JsonSchema\Types\Type;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;

#[Description('Tells how to fix a vulnerability (CVE, GHSA, ...): the version that fixes each affected package across all sources, and the patch and advisory links. A fix with fixed_in null has no known fixed version. Pass a vendor, product or ecosystem to see only that package.')]
#[IsReadOnly]
class GetRemediation extends Tool
{
    /**
     * NVD reference tags and OSV reference types that point at a fix or at the vendor's advice.
     */
    private const array REMEDIATION_TAGS = ['Patch', 'Mitigation', 'Vendor Advisory', 'Release Notes', 'FIX', 'ADVISORY'];

    /**
     * Handle the tool request.
     */
    public function handle(Request $request, VulnerabilityLookup $lookup): Response|ResponseFactory
    {
        $validated = $request->validate([
            'id' => ['required', 'string', 'max:255'],
            'vendor' => ['nullable', 'string', 'max:255'],
            'product' => ['nullable', 'string', 'max:255'],
            'ecosystem' => ['nullable', 'string', 'max:255'],
        ]);

        $records = $lookup->find($validated['id']);

        if ($records->isEmpty()) {
            return Response::error("No vulnerability found for [{$validated['id']}].");
        }

        $packageFilters = array_filter([
            'vendor' => $validated['vendor'] ?? null,
            'product' => $validated['product'] ?? null,
            'ecosystem' => $validated['ecosystem'] ?? null,
        ], fn (?string $value): bool => $value !== null);

        $activeRecords = ParsedRecord::query()
            ->whereKey($records->modelKeys())
            ->active()
            ->with(['source', 'versionRanges' => fn ($ranges) => $ranges
                ->whereIn('version_scope', ['range', 'any'])
                ->where($packageFilters)
                ->orderBy('ecosystem')
                ->orderBy('vendor')
                ->orderBy('product')
                ->orderBy('id')])
            ->orderBy('id')
            ->get();

        return Response::structured([
            'id' => $validated['id'],
            'fixes' => $activeRecords
                ->flatMap(fn (ParsedRecord $record) => $record->versionRanges->map(fn (VersionRange $range): array => $this->fix(new VulnerabilityMatch($record, $range))))
                ->values()
                ->all(),
            'references' => $this->remediationReferences($activeRecords),
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function fix(VulnerabilityMatch $match): array
    {
        return [
            'source' => $match->record->source->slug,
            'record_id' => $match->record->external_id,
            'fixed_in' => $match->fixedIn(),
            'confidence' => $match->isLowConfidence() ? 'low' : 'high',
            'affected_range' => (new VersionRangeResource($match->range))->resolve(),
        ];
    }

    /**
     * @param  Collection<int, ParsedRecord>  $records
     * @return list<array{url: string, tags: list<string>}>
     */
    private function remediationReferences(Collection $records): array
    {
        return array_values($records
            ->flatMap(fn (ParsedRecord $record): array => $record->references ?? [])
            ->filter(fn (array $reference): bool => array_intersect($reference['tags'], self::REMEDIATION_TAGS) !== [])
            ->unique('url')
            ->map(fn (array $reference): array => ['url' => $reference['url'], 'tags' => array_values($reference['tags'])])
            ->all());
    }

    /**
     * Get the tool's input schema.
     *
     * @return array<string, Type>
     */
    public function schema(JsonSchema $schema): array
    {
        return [
            'id' => $schema->string()
                ->description('The vulnerability id, e.g. "CVE-2021-44228" or "GHSA-jfh8-c2jp-5v3q".')
                ->required(),
            'vendor' => $schema->string()
                ->description('Only show fixes for this NVD vendor, e.g. "apache".'),
            'product' => $schema->string()
                ->description('Only show fixes for this product or package, e.g. "log4j" or "org.apache.logging.log4j:log4j-core".'),
            'ecosystem' => $schema->string()
                ->description('Only show fixes for this OSV ecosystem, e.g. "Maven", "npm" or "Debian:12".'),
        ];
    }
}
