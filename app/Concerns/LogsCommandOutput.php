<?php

namespace App\Concerns;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

/**
 * Writes a message to the console and to the application log, so scheduled runs
 * (whose console output is discarded) still leave a trace.
 *
 * @mixin Command
 */
trait LogsCommandOutput
{
    /**
     * @param  array<string, mixed>  $context
     */
    protected function logInfo(string $message, array $context = []): void
    {
        $this->info($message);
        Log::info($message, $this->logContext($context));
    }

    /**
     * @param  array<string, mixed>  $context
     */
    protected function logWarning(string $message, array $context = []): void
    {
        $this->warn($message);
        Log::warning($message, $this->logContext($context));
    }

    /**
     * @param  array<string, mixed>  $context
     */
    protected function logError(string $message, array $context = []): void
    {
        $this->error($message);
        Log::error($message, $this->logContext($context));
    }

    /**
     * @param  array<string, mixed>  $context
     * @return array<string, mixed>
     */
    private function logContext(array $context): array
    {
        return ['command' => $this->getName(), ...$context];
    }
}
