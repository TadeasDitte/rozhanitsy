<?php

use App\Http\Controllers\Api\V1\CheckController;
use App\Http\Controllers\Api\V1\ProductController;
use App\Http\Controllers\Api\V1\VulnerabilityController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::prefix('v1')->name('api.v1.')->middleware('throttle:60,1')->group(function () {
    Route::get('check', [CheckController::class, 'check'])->name('check');
    Route::post('check/batch', [CheckController::class, 'batch'])->name('check.batch');

    Route::get('vulnerabilities', [VulnerabilityController::class, 'index'])->name('vulnerabilities.index');
    Route::get('vulnerabilities/{id}', [VulnerabilityController::class, 'show'])->name('vulnerabilities.show');

    Route::get('products', [ProductController::class, 'index'])->name('products.index');
});
