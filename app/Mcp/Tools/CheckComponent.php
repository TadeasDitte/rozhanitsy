<?php

namespace App\Mcp\Tools;

use App\Services\ComponentChecker;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\JsonSchema\Types\Type;
use Illuminate\Validation\Rule;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Attributes\Description;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;

#[Description('Checks whether a product version is affected by any known vulnerability. Returns the matching vulnerabilities and the lowest version that fixes all of them. When the product name is ambiguous, returns the vendor / ecosystem candidates instead: call again with one of them.')]
#[IsReadOnly]
class CheckComponent extends Tool
{
    /**
     * Handle the tool request.
     */
    public function handle(Request $request, ComponentChecker $checker): ResponseFactory
    {
        $validated = $request->validate([
            'product' => ['required', 'string', 'max:255'],
            'version' => ['required', 'string', 'max:255'],
            'vendor' => ['nullable', 'string', 'max:255'],
            'ecosystem' => ['nullable', 'string', 'max:255'],
            'severity' => ['nullable', Rule::in(['LOW', 'MODERATE', 'MEDIUM', 'HIGH', 'CRITICAL'])],
            'min_score' => ['nullable', 'numeric', 'between:0,10'],
            'include_low_confidence' => ['nullable', 'boolean'],
        ]);

        return Response::structured($checker->check(
            $validated['product'],
            $validated['version'],
            $validated['vendor'] ?? null,
            $validated['ecosystem'] ?? null,
            $validated['severity'] ?? null,
            $validated['min_score'] ?? null,
            (bool) ($validated['include_low_confidence'] ?? false),
        ));
    }

    /**
     * Get the tool's input schema.
     *
     * @return array<string, Type>
     */
    public function schema(JsonSchema $schema): array
    {
        return [
            'product' => $schema->string()
                ->description('Product or package name, e.g. "wordpress", "lodash" or "symfony/http-kernel".')
                ->required(),
            'version' => $schema->string()
                ->description('The version to check, e.g. "6.9.2".')
                ->required(),
            'vendor' => $schema->string()
                ->description('NVD vendor name, e.g. "wordpress" or "apache". Narrows the search and finds CNA-only records.'),
            'ecosystem' => $schema->string()
                ->description('OSV ecosystem, e.g. "npm", "PyPI", "Packagist", "Debian:12". Distro ecosystems are only searched when named here.'),
            'severity' => $schema->string()
                ->enum(['LOW', 'MODERATE', 'MEDIUM', 'HIGH', 'CRITICAL'])
                ->description('Only return vulnerabilities of this CVSS severity.'),
            'min_score' => $schema->number()
                ->min(0)
                ->max(10)
                ->description('Only return vulnerabilities with a CVSS score at least this high.'),
            'include_low_confidence' => $schema->boolean()
                ->description('Also return matches whose affected range is uncertain, e.g. records that list no version bounds.'),
        ];
    }
}
