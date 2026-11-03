<?php

namespace App\Mcp\Tools;

use App\Models\Source;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Date;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;

#[Description('Reports how fresh the vulnerability data is, per source (NVD, OSV): when it was last synced, the newest modification among its records, how many records are parsed, and the backlog of records still waiting to be parsed, that failed to parse, or whose version ranges are not resolved yet. Use it to judge whether a recent vulnerability can be in the data yet.')]
#[IsReadOnly]
class SourceStatus extends Tool
{
    /**
     * Handle the tool request.
     */
    public function handle(): ResponseFactory
    {
        $sources = Source::query()
            ->with('syncState')
            ->withCount([
                'parsedRecords',
                'parsedRecords as unresolved_records_count' => fn (Builder $query) => $query->whereNull('resolved_at'),
                'ingestRecords as pending_records_count' => fn (Builder $query) => $query->where('processing_status', 'pending'),
                'ingestRecords as failed_records_count' => fn (Builder $query) => $query->where('processing_status', 'failed'),
            ])
            ->withMax('parsedRecords', 'last_modified_at')
            ->orderBy('id')
            ->get();

        return Response::structured([
            'sources' => $sources->map(fn (Source $source): array => [
                'slug' => $source->slug,
                'name' => $source->name,
                'url' => $source->url,
                'last_synced_at' => $source->syncState?->last_synced_at?->toIso8601String(),
                'latest_record_modified_at' => $source->parsed_records_max_last_modified_at !== null ? Date::parse($source->parsed_records_max_last_modified_at)->toIso8601String() : null,
                'parsed_records' => $source->parsed_records_count,
                'unresolved_records' => $source->unresolved_records_count,
                'pending_records' => $source->pending_records_count,
                'failed_records' => $source->failed_records_count,
            ])->all(),
        ]);
    }
}
