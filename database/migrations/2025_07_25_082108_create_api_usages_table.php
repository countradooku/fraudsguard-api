<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('api_usages', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->foreignId('api_key_id')->nullable()->constrained()->onDelete('set null');
            $table->string('endpoint');
            $table->string('method', 10);
            $table->integer('response_code');
            $table->integer('response_time_ms');
            $table->boolean('is_billable')->default(true);
            $table->boolean('is_over_limit')->default(false);
            $table->decimal('cost', 10, 6)->default(0); // Cost in dollars
            $table->string('ip_address')->nullable();
            $table->json('request_headers')->nullable();
            $table->text('request_body')->nullable();
            $table->timestamp('created_at')->useCurrent()->index();

            // Indexes for analytics and billing
            $table->index(['user_id', 'created_at']);
            $table->index(['api_key_id', 'created_at']);
            $table->index(['is_billable', 'created_at']);
            $table->index(['user_id', 'is_over_limit', 'created_at']);

            // Partitioning by month for performance (PostgreSQL)
            // This would be handled by a separate migration or DB admin task
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('api_usages');
    }
};
