<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Blacklisted Emails
        Schema::create('blacklisted_emails', function (Blueprint $table) {
            $table->id();
            $table->string('email_hash')->unique()->index();
            $table->string('reason');
            $table->integer('risk_weight')->default(100);
            $table->foreignId('reported_by')->nullable()->constrained('users');
            $table->integer('report_count')->default(1);
            $table->timestamp('last_seen_at');
            $table->timestamps();
        });

    }

    public function down(): void
    {
        Schema::dropIfExists('blacklisted_phones');
        Schema::dropIfExists('blacklisted_credit_cards');
        Schema::dropIfExists('blacklisted_ips');
        Schema::dropIfExists('blacklisted_emails');
    }
};
