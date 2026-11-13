<?php

namespace App\Ingestion\Parsers;

use App\Ingestion\ProductNameData;

interface LearnsProductNames
{
    /**
     * The names a source's own data uses for a product, tied to the names the
     * source's analysed data uses for it, as one ParsedRecord::raw_ranges value
     * shows them, together with the record's references, which may name the
     * product by the slug of a platform's extension directory.
     *
     * @param  array<int, array<string, mixed>>  $rawRanges
     * @param  array<int, mixed>  $references  ParsedRecord::references
     * @return list<ProductNameData>
     */
    public function productNames(array $rawRanges, array $references = []): array;
}
