<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Blacklisted IPs
        Schema::create('blacklisted_ips', function (Blueprint $table) {
            $table->id();
            $table->string('ip_hash')->unique()->index();
            $table->ipAddress()->index(); // Store actual IP for range queries
            $table->string('ip_version', 4)->default('v4'); // v4 or v6
            $table->string('reason');
            $table->integer('risk_weight')->default(100);
            $table->string('source')->nullable(); // tor, vpn, datacenter, etc
            $table->json('metadata')->nullable();
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->index(['ip_version', 'ip_address']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blacklisted_i_ps');
    }
};
