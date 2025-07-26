<?php

namespace App\Events;

use App\Models\FraudCheck;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Broadcasting\PrivateChannel;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class HighRiskDetectedEvent implements ShouldBroadcast
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public FraudCheck $fraudCheck;

    /**
     * Create a new event instance.
     */
    public function __construct(FraudCheck $fraudCheck)
    {
        $this->fraudCheck = $fraudCheck->load(['user', 'apiKey']);
    }

    /**
     * Get the channels the event should broadcast on.
     *
     * @return array<int, \Illuminate\Broadcasting\Channel>
     */
    public function broadcastOn(): array
    {
        return [
            new PrivateChannel('user.'.$this->fraudCheck->user_id),
            new PrivateChannel('high-risk-alerts'),
        ];
    }

    /**
     * Get the data to broadcast.
     *
     * @return array<string, mixed>
     */
    public function broadcastWith(): array
    {
        return [
            'fraud_check_id' => $this->fraudCheck->id,
            'risk_score' => $this->fraudCheck->risk_score,
            'decision' => $this->fraudCheck->decision,
            'failed_checks' => array_keys($this->fraudCheck->failed_checks ?? []),
            'user' => [
                'id' => $this->fraudCheck->user->id,
                'name' => $this->fraudCheck->user->name,
                'email' => $this->fraudCheck->user->email,
            ],
            'api_key' => $this->fraudCheck->apiKey ? [
                'id' => $this->fraudCheck->apiKey->id,
                'name' => $this->fraudCheck->apiKey->name,
            ] : null,
            'timestamp' => now()->toIso8601String(),
        ];
    }

    /**
     * The event's broadcast name.
     */
    public function broadcastAs(): string
    {
        return 'high-risk-detected';
    }
}
