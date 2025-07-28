<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

// Redirect to frontend app
// Route::get('/', function () {
//    return redirect(config('app.frontend_url', 'http://localhost:3000'));
// });
//
// // API documentation (optional, if using Swagger)
// Route::get('/api/documentation', function () {
//    return view('documentation.api');
// })->name('api.docs');

// Health check
Route::get('/health', function () {
    return response()->json([
        'status' => 'healthy',
        'timestamp' => now()->toIso8601String(),
        'services' => [
            'database' => \DB::connection()->getPdo() ? 'up' : 'down',
            'redis' => Illuminate\Support\Facades\Redis::ping() ? 'up' : 'down',
        ],
    ]);
});

// Catch-all route to redirect to frontend
Route::get('/{any}', function () {
    return redirect(config('app.frontend_url', 'http://localhost:3000'));
})->where('any', '.*');
