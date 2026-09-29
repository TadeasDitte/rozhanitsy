<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('version_ranges', function (Blueprint $table) {
            $table->id();
            $table->foreignId('parsed_record_id')->constrained()->cascadeOnDelete();
            $table->foreignId('format_id')->constrained('formats');
            $table->enum('type', ['a', 'h', 'o', 'u'])->default('u');
            $table->string('ecosystem')->nullable();
            $table->string('package_manager')->nullable();
            $table->string('vendor')->nullable();
            $table->string('product')->nullable();
            $table->string('version_incl_start')->nullable();
            $table->string('version_excl_start')->nullable();
            $table->string('version_incl_end')->nullable();
            $table->string('version_excl_end')->nullable();
            $table->enum('version_scope', ['range', 'any', 'na'])->default('range');
            $table->string('plugs_into')->nullable();
            $table->text('raw')->nullable();
            $table->timestamps();

            $table->index('parsed_record_id');
            $table->index(['vendor', 'product']);
            $table->index(['ecosystem', 'product']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('version_ranges');
    }
};
