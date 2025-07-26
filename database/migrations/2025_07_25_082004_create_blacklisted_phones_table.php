<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('blacklisted_phones', function (Blueprint $table) {
            $table->id();
            $table->string('phone_hash')->unique()->index();
            $table->string('country_code', 5)->nullable();
            $table->string('reason');
            $table->integer('risk_weight')->default(100);
            $table->string('type')->nullable(); // voip, mobile, landline
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->index(['country_code', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blacklisted_phones');
    }
};
