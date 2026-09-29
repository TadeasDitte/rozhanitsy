<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\ProductSearchRequest;
use App\Models\VersionRange;
use App\Services\VulnerabilityDataCache;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;

class ProductController extends Controller
{
    /**
     * Find the exact vendor / product / ecosystem names to use in checks.
     */
    public function index(ProductSearchRequest $request, VulnerabilityDataCache $cache): JsonResponse
    {
        $search = $request->validated('q');
        $ecosystem = $request->validated('ecosystem');

        $products = $cache->remember('products', [mb_strtolower($search), $ecosystem], fn (): array => VersionRange::query()
            ->select(['vendor', 'product', 'ecosystem'])
            ->selectRaw('count(distinct parsed_record_id) as vulnerability_count')
            ->whereLike('product', $search.'%')
            ->when($ecosystem, fn (Builder $query, string $ecosystem) => $query->where('ecosystem', $ecosystem))
            ->groupBy(['vendor', 'product', 'ecosystem'])
            ->orderByDesc('vulnerability_count')
            ->orderBy('product')
            ->limit(25)
            ->toBase()
            ->get()
            ->map(fn (object $row): array => [
                'vendor' => $row->vendor,
                'product' => $row->product,
                'ecosystem' => $row->ecosystem,
                'vulnerability_count' => (int) $row->vulnerability_count,
            ])
            ->all());

        return response()->json(['data' => $products]);
    }
}
