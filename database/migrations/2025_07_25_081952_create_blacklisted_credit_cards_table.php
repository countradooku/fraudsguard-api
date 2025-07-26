<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Blacklisted Credit Cards
        Schema::create('blacklisted_credit_cards', function (Blueprint $table) {
            $table->id();
            $table->string('card_hash')->unique()->index();
            $table->string('card_type')->nullable(); // visa, mastercard, etc
            $table->string('last_four', 4)->nullable();
            $table->string('reason');
            $table->integer('risk_weight')->default(100);
            $table->integer('chargeback_count')->default(0);
            $table->decimal('total_chargeback_amount', 10, 2)->default(0);
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->index(['card_type', 'last_four']);
        });

        // Blacklisted Phone Numbers
    }

    public function down(): void
    {
        Schema::dropIfExists('blacklisted_credit_cards');
    }
};
