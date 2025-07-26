<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Disposable Email Domains
        Schema::create('disposable_email_domains', function (Blueprint $table) {
            $table->id();
            $table->string('domain')->unique()->index();
            $table->string('source')->default('manual'); // manual, api, scraper
            $table->integer('risk_weight')->default(80);
            $table->boolean('is_active')->default(true);
            $table->timestamp('verified_at')->nullable();
            $table->timestamps();
        });

    }

    public function down(): void
    {
        Schema::dropIfExists('known_user_agents');
        Schema::dropIfExists('asns');
        Schema::dropIfExists('tor_exit_nodes');
        Schema::dropIfExists('disposable_email_domains');
    }
};
