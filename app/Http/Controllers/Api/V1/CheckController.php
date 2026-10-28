<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\BatchCheckRequest;
use App\Http\Requests\Api\V1\CheckRequest;
use App\Http\Resources\V1\VulnerabilityMatchResource;
use App\Services\VulnerabilityDataCache;
use App\Services\VulnerabilityMatcher;
use Illuminate\Http\JsonResponse;

class CheckController extends Controller
{
    public function __construct(
        private readonly VulnerabilityMatcher $matcher,
        private readonly VulnerabilityDataCache $cache,
    ) {}

    public function check(CheckRequest $request): JsonResponse
    {
        return response()->json([
            'data' => $this->result(
                $request->string('product'),
                $request->string('version'),
                $request->validated('vendor'),
                $request->validated('ecosystem'),
                $request->validated('cvss_severity'),
                $request->validated('cvss_score'),
                $request->boolean('include_low_confidence'),
            ),
        ]);
    }

    public function batch(BatchCheckRequest $request): JsonResponse
    {
        /** @var list<array{product: string, version: string, vendor?: ?string, ecosystem?: ?string, cvss_severity?: ?string, cvss_score?: int|float|null}> $packages */
        $packages = $request->validated('packages');

        return response()->json([
            'data' => array_map(fn (array $package): array => $this->result(
                $package['product'],
                $package['version'],
                $package['vendor'] ?? null,
                $package['ecosystem'] ?? null,
                $package['cvss_severity'] ?? null,
                $package['cvss_score'] ?? null,
                $request->boolean('include_low_confidence'),
            ), $packages),
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function result(string $product, string $version, ?string $vendor, ?string $ecosystem, ?string $cvssSeverity, ?float $cvssScore, bool $includeLowConfidence): array
    {
        return $this->cache->remember(
            'check',
            [$product, $version, $vendor, $ecosystem, $cvssSeverity, $cvssScore, $includeLowConfidence],
            fn (): array => $this->freshResult($product, $version, $vendor, $ecosystem, $cvssSeverity, $cvssScore, $includeLowConfidence),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function freshResult(string $product, string $version, ?string $vendor, ?string $ecosystem, ?string $cvssSeverity, ?float $cvssScore, bool $includeLowConfidence): array
    {
        $matches = $this->matcher->match($product, $version, $vendor, $ecosystem, $cvssSeverity, $cvssScore, $includeLowConfidence);
        $candidates = $vendor === null && $ecosystem === null ? $this->matcher->ambiguousCandidates($matches) : [];

        if ($candidates !== []) {
            return [
                'vendor' => $vendor,
                'product' => $product,
                'ecosystem' => $ecosystem,
                'cvss_severity' => $cvssSeverity,
                'cvss_score' => $cvssScore,
                'version' => $version,
                'ambiguous' => true,
                'candidates' => $candidates,
                'vulnerable' => null,
                'vulnerability_count' => 0,
                'recommended_version' => null,
                'vulnerabilities' => [],
            ];
        }

        return [
            'vendor' => $vendor,
            'product' => $product,
            'ecosystem' => $ecosystem,
            'cvss_severity' => $cvssSeverity,
            'cvss_score' => $cvssScore,
            'version' => $version,
            'ambiguous' => false,
            'candidates' => [],
            'vulnerable' => $matches->isNotEmpty(),
            'vulnerability_count' => $matches->count(),
            'recommended_version' => $this->matcher->recommendedVersion($matches),
            'vulnerabilities' => VulnerabilityMatchResource::collection($matches)->resolve(),
        ];
    }
}
