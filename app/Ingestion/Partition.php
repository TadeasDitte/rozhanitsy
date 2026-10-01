<?php

namespace App\Ingestion;

use Illuminate\Database\Eloquent\Builder;
use InvalidArgumentException;

final readonly class Partition
{
    public function __construct(
        public int $index,
        public int $count,
    ) {
        if ($count < 1 || $index < 0 || $index >= $count) {
            throw new InvalidArgumentException("Invalid partition [{$index}/{$count}]");
        }
    }

    public static function fromOption(?string $value): ?self
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (preg_match('/^(\d+)\/(\d+)$/', $value, $matches) !== 1) {
            throw new InvalidArgumentException("Partition must look like INDEX/COUNT, got [{$value}]");
        }

        return new self((int) $matches[1], (int) $matches[2]);
    }

    /**
     * @param  Builder<TModel>  $query
     * @return Builder<TModel>
     */
    public function apply(Builder $query): Builder
    {
        return $query->whereRaw('id % ? = ?', [$this->count, $this->index]);
    }

    public function toOption(): string
    {
        return "{$this->index}/{$this->count}";
    }
}
