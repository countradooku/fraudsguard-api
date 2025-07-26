<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Tor Exit Nodes
        Schema::create('tor_exit_nodes', function (Blueprint $table) {
            $table->id();
            $table->ipAddress()->unique()->index();
            $table->string('ip_version', 4)->default('v4');
            $table->string('node_id')->nullable();
            $table->string('nickname')->nullable();
            $table->integer('risk_weight')->default(90);
            $table->boolean('is_active')->default(true);
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->index(['ip_version', 'is_active']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('tor_exit_nodes');
    }
};
