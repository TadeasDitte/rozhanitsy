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
 * Lets a console command fan its work out over several `php artisan` child processes.
 *
 * Each child receives `--partition=FIRST_ID-LAST_ID` and only touches its own id range (see Partition),
 * so the command using this must accept that option and pass the partition down to its runner.
 *
 * @mixin Command
 */
trait RunsParallelWorkers
{
    /**
     * An invisible ASCII ACK byte, so ticks can be told apart from (and stripped out of) a worker's regular output.
     */
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

    /**
     * The onEach callback a worker hands its runner: prints one tick per record for the parent to count.
     */
    protected function workerProgressTick(): Closure
    {
        return fn () => $this->output->write(self::WORKER_PROGRESS_TICK);
    }

    /**
     * Splits the rows matched by `$pending` into id ranges, runs `$command` once per range in parallel child processes
     * and drives a progress bar from the ticks the workers print (see workerProgressTick) until all of them exit.
     *
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
            $this->error("{$name} exited with code {$result->exitCode()}");
            $this->line(trim($result->errorOutput()."\n".str_replace(self::WORKER_PROGRESS_TICK, '', $result->output())));
        }

        return $allSucceeded;
    }
}
