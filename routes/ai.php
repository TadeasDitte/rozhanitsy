<?php

use App\Mcp\Servers\RozhanitsyServer;
use Laravel\Mcp\Facades\Mcp;

Mcp::web('/mcp', RozhanitsyServer::class)
    ->middleware(['throttle:mcp']);
