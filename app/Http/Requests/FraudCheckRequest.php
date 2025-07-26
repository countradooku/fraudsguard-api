<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class FraudCheckRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true; // Authorization handled by middleware
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'email' => 'nullable|string|max:255',
            'ip' => 'nullable|string|max:45',
            'credit_card' => 'nullable|string|max:19|min:13',
            'phone' => 'nullable|string|max:20',
            'user_agent' => 'nullable|string|max:500',
            'domain' => 'nullable|string|max:255',
            'country' => 'nullable|string|size:2',
            'timezone' => 'nullable|string|max:50|timezone',
            'device_type' => 'nullable|string|in:mobile,desktop,tablet',
            'metadata' => 'nullable|array',
        ];
    }

    /**
     * Get custom messages for validator errors.
     */
    public function messages(): array
    {
        return [
            'email.max' => 'Email address is too long',
            'ip.max' => 'IP address is invalid',
            'credit_card.min' => 'Credit card number is too short',
            'credit_card.max' => 'Credit card number is too long',
            'country.size' => 'Country must be a 2-letter ISO code',
            'timezone.timezone' => 'Invalid timezone provided',
            'device_type.in' => 'Device type must be mobile, desktop, or tablet',
        ];
    }

    /**
     * Prepare the data for validation.
     */
    protected function prepareForValidation(): void
    {
        // Clean credit card number
        if ($this->has('credit_card')) {
            $this->merge([
                'credit_card' => preg_replace('/\s+/', '', $this->credit_card),
            ]);
        }

        // Clean phone number
        if ($this->has('phone')) {
            $this->merge([
                'phone' => preg_replace('/[^\d+\-\s()]/', '', $this->phone),
            ]);
        }

        // Uppercase country code
        if ($this->has('country')) {
            $this->merge([
                'country' => strtoupper($this->country),
            ]);
        }

        // Ensure at least one check parameter is provided
        if (! $this->hasAny(['email', 'ip', 'credit_card', 'phone'])) {
            abort(422, 'At least one parameter (email, ip, credit_card, or phone) must be provided');
        }
    }
}
