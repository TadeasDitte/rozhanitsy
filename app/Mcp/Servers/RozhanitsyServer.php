<?php

namespace App\Mcp\Servers;

use App\Mcp\Tools\CheckComponent;
use App\Mcp\Tools\GetRemediation;
use App\Mcp\Tools\GetVulnerability;
use App\Mcp\Tools\RecentChanges;
use App\Mcp\Tools\SourceStatus;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Attributes\Instructions;
use Laravel\Mcp\Server\Attributes\Name;
use Laravel\Mcp\Server\Attributes\Version;

#[Name('Rozhanitsy')]
#[Version('0.0.1')]
#[Instructions('Rozhanitsy is a vulnerability database built from NVD and OSV records. Use check-component to find out whether a product version is affected by known vulnerabilities and which version fixes them. Pass a vendor or ecosystem when you know it: without one, only NVD and language ecosystems (npm, PyPI, Packagist, ...) are searched, and distro packages such as Debian or Alpine are only matched when their ecosystem is named. If the answer is ambiguous, call the tool again with one of the returned candidates.')]
class RozhanitsyServer extends Server
{
    protected array $tools = [
        CheckComponent::class,
        GetRemediation::class,
        GetVulnerability::class,
        RecentChanges::class,
        SourceStatus::class,
    ];

    protected array $resources = [
        //
    ];

    protected array $prompts = [
        //
    ];
}
