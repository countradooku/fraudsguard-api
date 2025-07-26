<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>High Risk Fraud Alert</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 600px;
            margin: 20px auto;
            background: #fff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header {
            background: #dc2626;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .content {
            padding: 30px;
        }
        .alert-box {
            background: #fee2e2;
            border: 1px solid #fecaca;
            border-radius: 6px;
            padding: 20px;
            margin: 20px 0;
        }
        .risk-score {
            font-size: 48px;
            font-weight: bold;
            color: #dc2626;
            text-align: center;
            margin: 20px 0;
        }
        .details {
            background: #f9fafb;
            border-radius: 6px;
            padding: 20px;
            margin: 20px 0;
        }
        .detail-row {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #e5e7eb;
        }
        .detail-row:last-child {
            border-bottom: none;
        }
        .failed-checks {
            margin: 20px 0;
        }
        .failed-check {
            background: #fef2f2;
            border-left: 4px solid #dc2626;
            padding: 10px 15px;
            margin: 10px 0;
        }
        .action-button {
            display: inline-block;
            background: #3b82f6;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            margin: 10px 0;
        }
        .footer {
            background: #f9fafb;
            padding: 20px;
            text-align: center;
            font-size: 14px;
            color: #6b7280;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>⚠️ High Risk Fraud Alert</h1>
    </div>

    <div class="content">
        <div class="alert-box">
            <p style="margin: 0; font-weight: 500;">
                A high-risk fraud attempt has been detected on your account.
            </p>
        </div>

        <div class="risk-score">
            Risk Score: {{ $riskScore }}
        </div>

        <div class="details">
            <h3 style="margin-top: 0;">Detection Details</h3>

            <div class="detail-row">
                <strong>Check ID:</strong>
                <span>{{ $fraudCheck->id }}</span>
            </div>

            <div class="detail-row">
                <strong>Decision:</strong>
                <span style="color: #dc2626; font-weight: 500;">{{ ucfirst($decision) }}</span>
            </div>

            <div class="detail-row">
                <strong>Detected At:</strong>
                <span>{{ $timestamp->format('M d, Y H:i:s') }} UTC</span>
            </div>

            @if($fraudCheck->api_key_id)
                <div class="detail-row">
                    <strong>API Key Used:</strong>
                    <span>{{ $fraudCheck->apiKey->name }}</span>
                </div>
            @endif
        </div>

        @if(count($failedChecks) > 0)
            <div class="failed-checks">
                <h3>Failed Security Checks</h3>
                @foreach($failedChecks as $check => $details)
                    <div class="failed-check">
                        <strong>{{ ucfirst(str_replace('_', ' ', $check)) }}</strong>
                        @if(isset($details['reason']))
                            <p style="margin: 5px 0 0 0; font-size: 14px;">
                                {{ $details['reason'] }}
                            </p>
                        @endif
                    </div>
                @endforeach
            </div>
        @endif

        <div style="text-align: center; margin: 30px 0;">
            <a href="{{ config('app.url') }}/fraud-check/{{ $fraudCheck->id }}" class="action-button">
                View Full Details
            </a>
        </div>

        <div style="background: #fffbeb; border: 1px solid #fef3c7; border-radius: 6px; padding: 15px; margin-top: 20px;">
            <p style="margin: 0; font-size: 14px;">
                <strong>Recommended Actions:</strong>
            </p>
            <ul style="margin: 10px 0 0 20px; padding: 0; font-size: 14px;">
                <li>Review the failed checks and take appropriate action</li>
                <li>Consider blocking the source if this is a repeated offense</li>
                <li>Update your security rules if needed</li>
                <li>Contact support if you need assistance</li>
            </ul>
        </div>
    </div>

    <div class="footer">
        <p style="margin: 0;">
            This is an automated alert from FraudGuard.
        </p>
        <p style="margin: 5px 0 0 0;">
            © {{ date('Y') }} FraudGuard. All rights reserved.
        </p>
        <p style="margin: 10px 0 0 0; font-size: 12px;">
            You received this email because high-risk activity was detected on your account.
            <br>
            To manage your alert preferences, visit your account settings.
        </p>
    </div>
</div>
</body>
</html>
