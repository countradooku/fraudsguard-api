<?php

use App\Models\ASN;
use App\Models\DisposableEmailDomain;
use App\Models\KnownUserAgent;
use App\Models\TorExitNode;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Register fraud detection commands
Artisan::command('fraud:test-webhook {url} {--secret=}', function ($url, $secret = null) {
    $webhookService = app(\App\Services\WebhookService::class);

    $this->info('Testing webhook: ' . $url);

    $result = $webhookService->test($url, $secret);

    if ($result['success']) {
        $this->info('✅ Webhook test successful');
        $this->line('Status: ' . $result['status_code']);
    } else {
        $this->error('❌ Webhook test failed');
        $this->line('Error: ' . $result['error']);
    }
})->purpose('Test a webhook endpoint');

Artisan::command('fraud:stats', function () {
    $totalChecks = \App\Models\FraudCheck::count();
    $highRiskChecks = \App\Models\FraudCheck::where('risk_score', '>=', 80)->count();
    $avgRiskScore = \App\Models\FraudCheck::avg('risk_score');

    $this->table(['Metric', 'Value'], [
        ['Total Fraud Checks', number_format($totalChecks)],
        ['High Risk Checks', number_format($highRiskChecks)],
        ['Average Risk Score', round($avgRiskScore, 2)],
        ['High Risk %', $totalChecks > 0 ? round(($highRiskChecks / $totalChecks) * 100, 2) . '%' : '0%'],
    ]);

    // Data source stats
    $this->newLine();
    $this->line('Data Sources:');

    $torNodes = TorExitNode::where('is_active', true)->count();
    $disposableDomains = DisposableEmailDomain::where('is_active', true)->count();
    $asns = ASN::count();
    $userAgents = KnownUserAgent::count();

    $this->table(['Data Source', 'Count'], [
        ['Active Tor Exit Nodes', number_format($torNodes)],
        ['Disposable Email Domains', number_format($disposableDomains)],
        ['ASN Records', number_format($asns)],
        ['Known User Agents', number_format($userAgents)],
    ]);
})->purpose('Show fraud detection statistics');
