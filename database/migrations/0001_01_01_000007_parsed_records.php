<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('parsed_records', function (Blueprint $table) {
            $table->id();
            $table->foreignId('ingest_record_id')->constrained()->cascadeOnDelete();
            $table->foreignId('source_id')->constrained('sources')->cascadeOnDelete();
            $table->string('external_id');
            $table->decimal('cvss_score', 3, 1)->nullable();
            $table->string('cvss_vector')->nullable();
            $table->string('cvss_version')->nullable();
            $table->string('cvss_severity')->nullable();
            $table->text('description')->nullable();
            $table->timestamp('published_at')->nullable();
            $table->timestamp('last_modified_at')->nullable();
            $table->jsonb('weaknesses')->nullable();
            $table->jsonb('references')->nullable();
            $table->string('status')->nullable();
            $table->boolean('known_exploited')->default(false);
            $table->jsonb('raw_ranges');
            $table->timestamp('resolved_at')->nullable();
            $table->timestamps();

            $table->unique('ingest_record_id');
            $table->index(['source_id', 'external_id']);
            $table->index('resolved_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('parsed_records');
    }
};
