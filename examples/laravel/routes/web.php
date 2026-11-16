<?php

declare(strict_types=1);
use App\Http\Controllers\SsoController;
use Illuminate\Support\Facades\Route;

Route::get('/sso/login', [SsoController::class, 'login'])->name('sso.login')->block();
Route::get('/sso/callback', [SsoController::class, 'callback'])->name('sso.callback')->block();
Route::get('/sso/account', [SsoController::class, 'account'])->middleware('university.session-valid')->name('sso.account')->block();
Route::post('/sso/refresh', [SsoController::class, 'refresh'])->name('sso.refresh')->block();
Route::post('/sso/logout', [SsoController::class, 'logout'])->name('sso.logout')->block();
Route::post('/sso/global-logout', [SsoController::class, 'globalLogout'])->name('sso.global-logout')->block();
