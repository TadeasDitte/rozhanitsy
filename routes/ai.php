<?php

use Laravel\Mcp\Facades\Mcp;
use App\Mcp\Servers\RozhanistyServer;

Mcp::web('/mcp/weather', RozhanistyServer::class)
    ->middleware(['throttle:mcp']);
