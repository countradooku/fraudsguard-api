<?php

namespace App\Events;

use App\Models\ApiKey;
use App\Models\User;
use Illuminate\Broadcasting\Channel;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Broadcasting\PrivateChannel;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class FraudCheckPerformedEvent implements ShouldBroadcast
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public User $user;

    public ?ApiKey $apiKey;

    public array $result;

    /**
     * Create a new event instance.
     */
    public function __construct(User $user, ?ApiKey $apiKey, array $result)
    {
        $this->user = $user;
        $this->apiKey = $apiKey;
        $this->result = $result;
    }

    /**
     * Get the channels the event should broadcast on.
     *
     * @return array<int, Channel>
     */
    public function broadcastOn(): array
    {
        return [
            new PrivateChannel('user.'.$this->user->id),
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
            'risk_score' => $this->result['risk_score'],
            'decision' => $this->result['decision'],
            'id' => $this->result['id'],
            'timestamp' => now()->toIso8601String(),
        ];
    }

    /**
     * Determine if this event should broadcast.
     */
    public function shouldBroadcast(): bool
    {
        // Only broadcast high-risk events
        return $this->result['risk_score'] >= 80;
    }
}
