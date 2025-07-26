<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('asns', function (Blueprint $table) {
            $table->id();
            $table->unsignedInteger('asn')->unique()->index();
            $table->string('name');
            $table->string('organization')->nullable();
            $table->string('country_code', 2)->nullable();
            $table->string('type')->default('unknown'); // datacenter, residential, mobile, education, government
            $table->integer('risk_weight')->default(0);
            $table->boolean('is_hosting')->default(false);
            $table->boolean('is_vpn')->default(false);
            $table->boolean('is_proxy')->default(false);
            $table->json('ip_ranges')->nullable(); // CIDR ranges
            $table->timestamp('verified_at')->nullable();
            $table->timestamps();

            $table->index(['type', 'risk_weight']);
            $table->index(['country_code', 'type']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('a_s_ns');
    }
};
