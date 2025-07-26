<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class CreateApiKeyRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'name' => [
                'required',
                'string',
                'max:255',
                'min:3',
            ],
            'permissions' => [
                'nullable',
                'array',
            ],
            'permissions.*' => [
                'string',
                'in:fraud_check,read_stats,manage_blacklist,webhook_access,export_data',
            ],
            'expires_at' => [
                'nullable',
                'date',
                'after:now',
            ],
            'rate_limit' => [
                'nullable',
                'integer',
                'min:10',
                'max:1000000',
            ],
            'allowed_ips' => [
                'nullable',
                'array',
            ],
            'allowed_ips.*' => [
                'ip',
            ],
            'webhook_url' => [
                'nullable',
                'url',
                'max:255',
            ],
        ];
    }

    /**
     * Get custom messages for validator errors.
     */
    public function messages(): array
    {
        return [
            'name.required' => 'API key name is required',
            'name.min' => 'API key name must be at least 3 characters',
            'permissions.*.in' => 'Invalid permission specified',
            'expires_at.after' => 'Expiration date must be in the future',
            'rate_limit.min' => 'Rate limit must be at least 10 requests per hour',
            'allowed_ips.*.ip' => 'Invalid IP address format',
            'webhook_url.url' => 'Invalid webhook URL format',
        ];
    }
}
