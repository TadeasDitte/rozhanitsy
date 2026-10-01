<?php

namespace App\Ingestion;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

final readonly class Partition
{
    public function __construct(
        public int $firstId,
        public int $lastId,
    ) {
        if ($firstId < 0 || $lastId < $firstId) {
            throw new InvalidArgumentException("Invalid partition [{$firstId}-{$lastId}]");
        }
    }

    public static function fromOption(?string $value): ?self
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (preg_match('/^(\d+)-(\d+)$/', $value, $matches) !== 1) {
            throw new InvalidArgumentException("Partition must look like FIRST_ID-LAST_ID, got [{$value}]");
        }

        return new self((int) $matches[1], (int) $matches[2]);
    }

    /**
     * Splits the rows matched by `$query` into at most `$count` contiguous id ranges holding roughly the same number of rows.
     *
     * Contiguous ranges keep each worker's chunk query a plain primary key range scan instead of a parallel table scan.
     *
     * @param  Builder<covariant Model>  $query
     * @return list<self>
     */
    public static function split(Builder $query, int $count): array
    {
        $buckets = $query->clone()
            ->select('id')
            ->selectRaw('ntile(?) over (order by id) as bucket', [$count])
            ->toBase();

        return array_values(DB::query()
            ->fromSub($buckets, 'buckets')
            ->selectRaw('min(id) as first_id, max(id) as last_id')
            ->groupBy('bucket')
            ->orderBy('bucket')
            ->get()
            ->map(fn (object $bucket) => new self((int) $bucket->first_id, (int) $bucket->last_id))
            ->all());
    }

    /**
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  Builder<TModel>  $query
     * @return Builder<TModel>
     */
    public function apply(Builder $query): Builder
    {
        return $query->whereBetween('id', [$this->firstId, $this->lastId]);
    }

    public function toOption(): string
    {
        return "{$this->firstId}-{$this->lastId}";
    }
}
