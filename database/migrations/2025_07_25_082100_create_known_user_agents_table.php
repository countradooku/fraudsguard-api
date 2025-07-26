<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('known_user_agents', function (Blueprint $table) {
            $table->id();
            $table->text('user_agent');
            $table->string('user_agent_hash')->unique()->index();
            $table->string('type'); // bot, scraper, browser, mobile, api
            $table->string('name')->nullable(); // Chrome, Firefox, Googlebot, etc
            $table->string('version')->nullable();
            $table->integer('risk_weight')->default(0);
            $table->boolean('is_outdated')->default(false);
            $table->date('eol_date')->nullable(); // End of life date
            $table->timestamps();

            $table->index(['type', 'is_outdated']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('known_user_agents');
    }
};
