<?php

namespace App\Mail;

use App\Models\FraudCheck;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Attachment;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class HighRiskAlertMail extends Mailable implements ShouldQueue
{
    use Queueable, SerializesModels;

    public FraudCheck $fraudCheck;

    /**
     * Create a new message instance.
     */
    public function __construct(FraudCheck $fraudCheck)
    {
        $this->fraudCheck = $fraudCheck;
    }

    /**
     * Get the message envelope.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'High Risk Fraud Alert - Immediate Action Required',
        );
    }

    /**
     * Get the message content definition.
     */
    public function content(): Content
    {
        return new Content(
            view: 'emails.high-risk-alert',
            with: [
                'fraudCheck' => $this->fraudCheck,
                'riskScore' => $this->fraudCheck->risk_score,
                'decision' => $this->fraudCheck->decision,
                'failedChecks' => $this->fraudCheck->failed_checks,
                'timestamp' => $this->fraudCheck->created_at,
            ],
        );
    }

    /**
     * Get the attachments for the message.
     *
     * @return array<int, Attachment>
     */
    public function attachments(): array
    {
        return [];
    }
}
