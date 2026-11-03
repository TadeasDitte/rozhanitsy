<?php

test('answers MCP clients at /mcp', function () {
    $response = $this->postJson('/mcp', [
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'initialize',
        'params' => [
            'protocolVersion' => '2025-11-25',
            'capabilities' => [],
            'clientInfo' => ['name' => 'test-client', 'version' => '1.0.0'],
        ],
    ]);

    $response->assertOk()
        ->assertJsonPath('result.serverInfo.name', 'Rozhanitsy');
});
