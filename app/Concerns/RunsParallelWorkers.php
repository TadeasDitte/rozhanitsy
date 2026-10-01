<?php

namespace App\Concerns;

use App\Ingestion\Partition;
use Closure;
use Illuminate\Console\Command;
use Illuminate\Process\Pool;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Sleep;
use InvalidArgumentException;

/**
 * Lets a console command fan its work out over several `php artisan` child processes.
 *
 * Each child receives `--partition=INDEX/COUNT` and only touches its own slice of rows (see Partition),
 * so the command using this must accept that option and pass the partition down to its runner.
 *
 * @mixin Command
 */
trait RunsParallelWorkers
{
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

    /**
     * Runs `$command` in `$workers` parallel child processes and drives a progress bar from `$remaining`
     * (a callback returning how many rows are still left to process) until all of them exit.
     *
     * @param  list<string>  $arguments
     * @param  Closure(): int  $remaining
     * @return bool whether every worker exited successfully
     */
    protected function runInWorkers(string $command, array $arguments, int $workers, int $total, Closure $remaining): bool
    {
        $bar = $this->output->createProgressBar($total);
        $bar->start();

        $pool = Process::pool(function (Pool $pool) use ($command, $arguments, $workers) {
            foreach (range(0, $workers - 1) as $index) {
                $pool->as("worker {$index}")->forever()->command([
                    PHP_BINARY,
                    base_path('artisan'),
                    $command,
                    ...$arguments,
                    '--partition='.(new Partition($index, $workers))->toOption(),
                    '--no-interaction',
                ]);
            }
        })->start();

        while ($pool->running()->isNotEmpty()) {
            $bar->setProgress(max(0, $total - $remaining()));
            Sleep::for(500)->milliseconds();
        }

        $bar->setProgress(max(0, $total - $remaining()));
        $bar->finish();
        $this->newLine();

        $allSucceeded = true;

        foreach ($pool->wait()->collect() as $name => $result) {
            if ($result->successful()) {
                continue;
            }

            $allSucceeded = false;
            $this->error("{$name} exited with code {$result->exitCode()}");
            $this->line(trim($result->errorOutput()."\n".$result->output()));
        }

        return $allSucceeded;
    }
}
