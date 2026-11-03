<?php

namespace App\Services;

use App\Http\Resources\V1\VulnerabilityMatchResource;

/**
 * Answers whether a product version is vulnerable, as served by the check API and the MCP server.
 */
final readonly class ComponentChecker
{
    public function __construct(
        private VulnerabilityMatcher $matcher,
        private VulnerabilityDataCache $cache,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function check(string $product, string $version, ?string $vendor = null, ?string $ecosystem = null, ?string $severity = null, ?float $minScore = null, bool $includeLowConfidence = false): array
    {
        return $this->cache->remember(
            'check',
            [$product, $version, $vendor, $ecosystem, $severity, $minScore, $includeLowConfidence],
            fn (): array => $this->freshResult($product, $version, $vendor, $ecosystem, $severity, $minScore, $includeLowConfidence),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function freshResult(string $product, string $version, ?string $vendor, ?string $ecosystem, ?string $severity, ?float $minScore, bool $includeLowConfidence): array
    {
        $matches = $this->matcher->match($product, $version, $vendor, $ecosystem, $severity, $minScore, $includeLowConfidence);
        $candidates = $vendor === null && $ecosystem === null ? $this->matcher->ambiguousCandidates($matches) : [];

        if ($candidates !== []) {
            return [
                'vendor' => $vendor,
                'product' => $product,
                'ecosystem' => $ecosystem,
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
