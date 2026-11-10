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
            $table->string('product_key')->nullable()->after('product');
            $table->index('product_key');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('version_ranges', function (Blueprint $table) {
            $table->dropIndex(['product_key']);
            $table->dropColumn('product_key');
        });
    }
};
