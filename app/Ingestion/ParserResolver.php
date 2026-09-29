<?php

namespace App\Ingestion;

use App\Ingestion\Parsers\RangeParser;
use App\Ingestion\Parsers\SourceRecordParser;
use App\Models\Format;

final class ParserResolver
{
    public function recordParser(string $slug): ?SourceRecordParser
    {
        $class = 'App\\Ingestion\\Parsers\\'.strtoupper($slug).'RecordParser';

        return class_exists($class) ? app($class) : null;
    }

    public function rangeParser(string $slug): ?RangeParser
    {
        $class = 'App\\Ingestion\\Parsers\\'.strtoupper($slug).'RangeParser';

        return class_exists($class) ? app($class) : null;
    }

    public function formatId(string $slug): ?int
    {
        // why doesnt this use db?
        $name = match ($slug) {
            'nvd' => 'cpe',
            'osv' => 'purl',
            default => null,
        };

        if ($name === null) {
            return null;
        }

        return Format::where('name', $name)->value('id');
    }
}
