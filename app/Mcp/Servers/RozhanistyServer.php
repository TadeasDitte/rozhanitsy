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

#[Name('Rozhanisty Server')]
#[Version('0.0.1')]
#[Instructions('Instructions describing how to use the server and its features.')]
class RozhanistyServer extends Server
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
