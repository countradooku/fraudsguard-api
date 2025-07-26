<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('fraud_checks', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->foreignId('api_key_id')->nullable()->constrained()->onDelete('set null');

            // Hashed data for privacy
            $table->string('email_hash')->nullable()->index();
            $table->string('ip_hash')->nullable()->index();
            $table->string('credit_card_hash')->nullable()->index();
            $table->string('phone_hash')->nullable()->index();

            // Original data for checks (encrypted)
            $table->text('email_encrypted')->nullable();
            $table->text('ip_encrypted')->nullable();
            $table->text('credit_card_encrypted')->nullable();
            $table->text('phone_encrypted')->nullable();

            // Check metadata
            $table->string('user_agent')->nullable();
            $table->string('domain')->nullable();
            $table->json('headers')->nullable();

            // Results
            $table->integer('risk_score')->default(0);
            $table->json('check_results');
            $table->json('failed_checks')->nullable();
            $table->json('passed_checks')->nullable();
            $table->string('decision')->default('review'); // allow, review, block

            // Performance metrics
            $table->integer('processing_time_ms')->nullable();

            $table->timestamps();

            // Composite indexes for performance
            $table->index(['user_id', 'created_at']);
            $table->index(['risk_score', 'created_at']);
            $table->index(['decision', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('fraud_checks');
    }
};
