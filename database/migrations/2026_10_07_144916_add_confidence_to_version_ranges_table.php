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
        Schema::table('version_ranges', function (Blueprint $table) {
            $table->enum('confidence', ['high', 'low'])->default('high')->after('version_scope');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('version_ranges', function (Blueprint $table) {
            $table->dropColumn('confidence');
        });
    }
};
