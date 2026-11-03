<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\BatchCheckRequest;
use App\Http\Requests\Api\V1\CheckRequest;
use App\Services\ComponentChecker;
use Illuminate\Http\JsonResponse;

class CheckController extends Controller
{
    public function __construct(private readonly ComponentChecker $checker) {}

    public function check(CheckRequest $request): JsonResponse
    {
        return response()->json([
            'data' => $this->checker->check(
                $request->string('product'),
                $request->string('version'),
                $request->validated('vendor'),
                $request->validated('ecosystem'),
                $request->validated('severity'),
                $request->validated('min_score'),
                $request->boolean('include_low_confidence'),
            ),
        ]);
    }

    public function batch(BatchCheckRequest $request): JsonResponse
    {
        /** @var list<array{product: string, version: string, vendor?: ?string, ecosystem?: ?string, severity?: ?string, min_score?: int|float|null}> $packages */
        $packages = $request->validated('packages');

        return response()->json([
            'data' => array_map(fn (array $package): array => $this->checker->check(
                $package['product'],
                $package['version'],
                $package['vendor'] ?? null,
                $package['ecosystem'] ?? null,
                $package['severity'] ?? null,
                $package['min_score'] ?? null,
                $request->boolean('include_low_confidence'),
            ), $packages),
        ]);
    }
}
