<?php

namespace App\Ingestion\Support;

/**
 * Parses a CVSS vector string and computes its base score.
 *
 * OSV stores the vector string (not a number) in `severity[].score`, so the
 * numeric score has to be derived. CVSS v2.0, v3.0/v3.1 and v4.0 base scores
 * are all computed, v4.0 by CvssV4, and an incomplete vector keeps its
 * version/vector with a null score.
 */
final readonly class Cvss
{
    public function __construct(
        public string $version,
        public string $vector,
        public ?float $baseScore,
        public ?string $baseSeverity,
    ) {}

    public static function fromVector(string $vector): ?self
    {
        $vector = trim($vector);

        if (preg_match('#^CVSS:(3\.0|3\.1|4\.0)/(.+)$#i', $vector, $m) === 1) {
            if ($m[1] === '4.0') {
                $score = CvssV4::score(self::metrics($m[2]));

                return new self('4.0', $vector, $score, self::severity($score));
            }

            $score = self::scoreV3(self::metrics($m[2]));

            return new self($m[1], $vector, $score, self::severity($score));
        }

        $body = preg_match('#^CVSS:2\.0/(.+)$#i', $vector, $m) === 1 ? $m[1] : $vector;
        $metrics = self::metrics($body);

        if (isset($metrics['AV'], $metrics['AC'], $metrics['Au'], $metrics['C'], $metrics['I'], $metrics['A'])) {
            $score = self::scoreV2($metrics);

            return $score === null ? null : new self('2.0', $vector, $score, self::severityV2($score));
        }

        return null;
    }

    /**
     * @return array<string, string>
     */
    private static function metrics(string $body): array
    {
        $metrics = [];

        foreach (explode('/', $body) as $pair) {
            $kv = explode(':', $pair, 2);

            if (count($kv) === 2 && $kv[0] !== '' && $kv[1] !== '') {
                $metrics[$kv[0]] = $kv[1];
            }
        }

        return $metrics;
    }

    /**
     * @param  array<string, string>  $m
     */
    private static function scoreV3(array $m): ?float
    {
        foreach (['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as $key) {
            if (! isset($m[$key])) {
                return null;
            }
        }

        $scopeChanged = $m['S'] === 'C';

        $av = ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2][$m['AV']] ?? null;
        $ac = ['L' => 0.77, 'H' => 0.44][$m['AC']] ?? null;
        $pr = $scopeChanged
            ? (['N' => 0.85, 'L' => 0.68, 'H' => 0.5][$m['PR']] ?? null)
            : (['N' => 0.85, 'L' => 0.62, 'H' => 0.27][$m['PR']] ?? null);
        $ui = ['N' => 0.85, 'R' => 0.62][$m['UI']] ?? null;
        $impactScores = ['N' => 0.0, 'L' => 0.22, 'H' => 0.56];

        if ($av === null || $ac === null || $pr === null || $ui === null
            || ! isset($impactScores[$m['C']], $impactScores[$m['I']], $impactScores[$m['A']])) {
            return null;
        }

        $c = $impactScores[$m['C']];
        $i = $impactScores[$m['I']];
        $a = $impactScores[$m['A']];

        $iss = 1 - ((1 - $c) * (1 - $i) * (1 - $a));
        $impact = $scopeChanged
            ? 7.52 * ($iss - 0.029) - 3.25 * (($iss - 0.02) ** 15)
            : 6.42 * $iss;

        if ($impact <= 0) {
            return 0.0;
        }

        $exploitability = 8.22 * $av * $ac * $pr * $ui;
        $base = $scopeChanged ? 1.08 * ($impact + $exploitability) : $impact + $exploitability;

        return self::roundUp(min($base, 10.0));
    }

    /**
     * @param  array<string, string>  $m
     */
    private static function scoreV2(array $m): ?float
    {
        $av = ['L' => 0.395, 'A' => 0.646, 'N' => 1.0][$m['AV']] ?? null;
        $ac = ['H' => 0.35, 'M' => 0.61, 'L' => 0.71][$m['AC']] ?? null;
        $au = ['M' => 0.45, 'S' => 0.56, 'N' => 0.704][$m['Au']] ?? null;
        $ciaScores = ['N' => 0.0, 'P' => 0.275, 'C' => 0.66];

        if ($av === null || $ac === null || $au === null
            || ! isset($ciaScores[$m['C']], $ciaScores[$m['I']], $ciaScores[$m['A']])) {
            return null;
        }

        $c = $ciaScores[$m['C']];
        $i = $ciaScores[$m['I']];
        $a = $ciaScores[$m['A']];

        $impact = 10.41 * (1 - (1 - $c) * (1 - $i) * (1 - $a));
        $exploitability = 20 * $av * $ac * $au;
        $f = $impact === 0.0 ? 0.0 : 1.176;

        $base = ((0.6 * $impact) + (0.4 * $exploitability) - 1.5) * $f;

        return round($base, 1);
    }

    /**
     * CVSS v3.1 Roundup: round up to the nearest 0.1, immune to float noise.
     */
    private static function roundUp(float $value): float
    {
        $int = (int) round($value * 100000);

        if ($int % 10000 === 0) {
            return $int / 100000;
        }

        return (intdiv($int, 10000) + 1) / 10.0;
    }

    /**
     * The qualitative rating scale v3.0, v3.1 and v4.0 share.
     */
    private static function severity(?float $score): ?string
    {
        if ($score === null) {
            return null;
        }

        return match (true) {
            $score == 0.0 => 'None',
            $score < 4.0 => 'Low',
            $score < 7.0 => 'Medium',
            $score < 9.0 => 'High',
            default => 'Critical',
        };
    }

    private static function severityV2(?float $score): ?string
    {
        if ($score === null) {
            return null;
        }

        return match (true) {
            $score < 4.0 => 'Low',
            $score < 7.0 => 'Medium',
            default => 'High',
        };
    }
}
