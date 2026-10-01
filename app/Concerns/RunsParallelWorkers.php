<?php

namespace App\Concerns;

use App\Ingestion\Partition;
use Closure;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Process\Pool;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Sleep;
use InvalidArgumentException;

/**
 * @mixin Command
 */
trait RunsParallelWorkers
{
    use LogsCommandOutput;

    private const WORKER_PROGRESS_TICK = "\x06";

    protected function workerCount(): int
    {
        $workers = filter_var($this->option('workers'), FILTER_VALIDATE_INT);

        if ($workers === false || $workers < 1) {
            throw new InvalidArgumentException('--workers must be a positive integer');
        }

        return $workers;
    }

    protected function partition(): ?Partition
    {
        return Partition::fromOption($this->option('partition'));
    }

    protected function workerProgressTick(): Closure
    {
        return fn () => $this->output->write(self::WORKER_PROGRESS_TICK);
    }

    /**
     * @param  list<string>  $arguments
     * @param  Builder<covariant Model>  $pending
     * @return bool whether every worker exited successfully
     */
    protected function runInWorkers(string $command, array $arguments, int $workers, Builder $pending): bool
    {
        $total = $pending->clone()->count();
        $partitions = Partition::split($pending, $workers);

        $bar = $this->output->createProgressBar($total);
        $bar->start();

        $pool = Process::pool(function (Pool $pool) use ($command, $arguments, $partitions) {
            foreach ($partitions as $index => $partition) {
                $pool->as("worker {$index}")->forever()->command([
                    PHP_BINARY,
                    base_path('artisan'),
                    $command,
                    ...$arguments,
                    '--partition='.$partition->toOption(),
                    '--no-interaction',
                ]);
            }
        })->start(function (string $type, string $buffer) use ($bar) {
            if ($type === 'out') {
                $bar->advance(substr_count($buffer, self::WORKER_PROGRESS_TICK));
            }
        });

        while ($pool->running()->isNotEmpty()) {
            Sleep::for(200)->milliseconds();
        }

        $bar->display();
        $this->newLine();

        $allSucceeded = true;

        foreach ($pool->wait()->collect() as $name => $result) {
            if ($result->successful()) {
                continue;
            }

            $allSucceeded = false;
            $output = trim($result->errorOutput()."\n".str_replace(self::WORKER_PROGRESS_TICK, '', $result->output()));

            $this->logError("{$name} exited with code {$result->exitCode()}", [
                'worker_command' => $command,
                'arguments' => $arguments,
                'exit_code' => $result->exitCode(),
                'output' => $output,
            ]);
            $this->line($output);
        }

        return $allSucceeded;
    }
}
