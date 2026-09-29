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
        Schema::create('trf', function (Blueprint $table) {
            $table->id();
            $table->string('format_version');
            $table->enum('type', ['a', 'o', 'h', 'u'])->default('u');
            $table->string('ecosystem')->nullable();
            $table->string('package_manager')->nullable();
            $table->string('vendor');
            $table->string('product');
            $table->string('version_incl_start')->nullable();
            $table->string('version_excl_start')->nullable();
            $table->string('version_incl_end')->nullable();
            $table->string('version_excl_end')->nullable();
            $table->string('plugs_into')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('trf');
    }
};
