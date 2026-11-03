<?php

namespace App\Mcp\Tools;

use App\Models\Alias;
use App\Models\ParsedRecord;
use Carbon\CarbonInterface;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\JsonSchema\Types\Type;
use Illuminate\Support\Facades\Date;
use Illuminate\Validation\Rule;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;

#[Description('Lists the vulnerabilities their source published or modified since a date (the last 7 days by default), most recently modified first. Narrow it to a vendor, product or ecosystem to watch a dependency, or to a severity or known exploitation to triage. has_more tells whether the limit cut the list short.')]
#[IsReadOnly]
class RecentChanges extends Tool
{
    /**
     * Handle the tool request.
     */
    public function handle(Request $request): ResponseFactory
    {
        $validated = $request->validate([
            'since' => ['nullable', 'date'],
            'vendor' => ['nullable', 'string', 'max:255'],
            'product' => ['nullable', 'string', 'max:255'],
            'ecosystem' => ['nullable', 'string', 'max:255'],
            'severity' => ['nullable', Rule::in(['LOW', 'MODERATE', 'MEDIUM', 'HIGH', 'CRITICAL'])],
            'known_exploited' => ['nullable', 'boolean'],
            'limit' => ['nullable', 'integer', 'min:1', 'max:100'],
        ]);

        $since = isset($validated['since']) ? Date::parse($validated['since']) : Date::now()->subDays(7);
        $limit = $validated['limit'] ?? 25;
        $knownExploited = $validated['known_exploited'] ?? null;

        $packageFilters = array_filter([
            'vendor' => $validated['vendor'] ?? null,
            'product' => $validated['product'] ?? null,
            'ecosystem' => $validated['ecosystem'] ?? null,
        ], fn (?string $value): bool => $value !== null);

        $records = ParsedRecord::query()
            ->active()
            ->where('last_modified_at', '>=', $since)
            ->when($packageFilters !== [], fn (Builder $query) => $query->whereHas('versionRanges', fn (Builder $ranges) => $ranges->where($packageFilters)))
            ->when($validated['severity'] ?? null, fn (Builder $query, string $severity) => $query->whereLike('cvss_severity', $severity))
            ->when($knownExploited !== null, fn (Builder $query) => $query->where('known_exploited', (bool) $knownExploited))
            ->with(['source', 'aliases'])
            ->orderByDesc('last_modified_at')
            ->orderByDesc('id')
            ->limit($limit + 1)
            ->get();

        return Response::structured([
            'since' => $since->toIso8601String(),
            'has_more' => $records->count() > $limit,
            'vulnerabilities' => $records->take($limit)->map(fn (ParsedRecord $record): array => $this->summary($record, $since))->values()->all(),
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(ParsedRecord $record, CarbonInterface $since): array
    {
        return [
            'id' => $record->external_id,
            'source' => $record->source->slug,
            'aliases' => $record->aliases->map(fn (Alias $alias): string => $alias->alias)->all(),
            'change' => $record->published_at !== null && $record->published_at->gte($since) ? 'published' : 'modified',
            'description' => $record->description,
            'cvss_score' => $record->cvss_score !== null ? (float) $record->cvss_score : null,
            'severity' => $record->cvss_severity,
            'known_exploited' => $record->known_exploited,
            'published_at' => $record->published_at?->toIso8601String(),
            'last_modified_at' => $record->last_modified_at?->toIso8601String(),
        ];
    }

    /**
     * Get the tool's input schema.
     *
     * @return array<string, Type>
     */
    public function schema(JsonSchema $schema): array
    {
        return [
            'since' => $schema->string()
                ->description('Only list changes on or after this date or time, e.g. "2026-10-01". Defaults to 7 days ago.'),
            'vendor' => $schema->string()
                ->description('Only list vulnerabilities affecting this NVD vendor, e.g. "apache".'),
            'product' => $schema->string()
                ->description('Only list vulnerabilities affecting this product or package, e.g. "wordpress" or "lodash".'),
            'ecosystem' => $schema->string()
                ->description('Only list vulnerabilities affecting this OSV ecosystem, e.g. "npm", "PyPI" or "Debian:12".'),
            'severity' => $schema->string()
                ->enum(['LOW', 'MODERATE', 'MEDIUM', 'HIGH', 'CRITICAL'])
                ->description('Only list vulnerabilities of this CVSS severity.'),
            'known_exploited' => $schema->boolean()
                ->description('Only list vulnerabilities that are (true) or are not (false) known to be exploited.'),
            'limit' => $schema->integer()
                ->min(1)
                ->max(100)
                ->description('The most vulnerabilities to list. Defaults to 25.'),
        ];
    }
}
