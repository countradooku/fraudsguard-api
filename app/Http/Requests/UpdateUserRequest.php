<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateUserRequest extends FormRequest
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
        $userId = $this->user()->id;

        return [
            'name' => [
                'sometimes',
                'required',
                'string',
                'max:255',
                'min:2',
            ],
            'email' => [
                'sometimes',
                'required',
                'string',
                'email',
                'max:255',
                Rule::unique('users')->ignore($userId),
            ],
            'company_name' => [
                'nullable',
                'string',
                'max:255',
            ],
            'phone' => [
                'nullable',
                'string',
                'max:20',
            ],
            'timezone' => [
                'nullable',
                'string',
                'timezone',
            ],
            'notification_preferences' => [
                'nullable',
                'array',
            ],
            'notification_preferences.email_alerts' => [
                'boolean',
            ],
            'notification_preferences.high_risk_alerts' => [
                'boolean',
            ],
            'notification_preferences.weekly_reports' => [
                'boolean',
            ],
            'notification_preferences.api_limit_alerts' => [
                'boolean',
            ],
            'webhook_url' => [
                'nullable',
                'url',
                'max:255',
            ],
            'webhook_secret' => [
                'nullable',
                'string',
                'min:16',
                'max:64',
            ],
            'webhook_min_risk_score' => [
                'nullable',
                'integer',
                'min:0',
                'max:100',
            ],
            'allowed_ips' => [
                'nullable',
                'array',
            ],
            'allowed_ips.*' => [
                'ip',
            ],
        ];
    }

    /**
     * Get custom messages for validator errors.
     */
    public function messages(): array
    {
        return [
            'name.min' => 'Name must be at least 2 characters',
            'email.unique' => 'This email address is already in use',
            'webhook_secret.min' => 'Webhook secret must be at least 16 characters for security',
            'webhook_min_risk_score.min' => 'Minimum risk score cannot be negative',
            'webhook_min_risk_score.max' => 'Minimum risk score cannot exceed 100',
            'allowed_ips.*.ip' => 'Invalid IP address format',
        ];
    }

    /**
     * Prepare the data for validation.
     */
    protected function prepareForValidation(): void
    {
        // Remove null values from notification preferences
        if ($this->has('notification_preferences')) {
            $this->merge([
                'notification_preferences' => array_filter($this->notification_preferences),
            ]);
        }
    }
}
