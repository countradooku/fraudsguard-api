<?php

namespace App\Actions\Fortify;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Contracts\CreatesNewUsers;

class CreateNewUser implements CreatesNewUsers
{
    use PasswordValidationRules;

    /**
     * Validate and create a newly registered user.
     *
     * @param  array<string, string>  $input
     */
    public function create(array $input): User
    {
        Validator::make($input, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => $this->passwordRules(),
            'company_name' => ['nullable', 'string', 'max:255'],
        ])->validate();

        $user = User::create([
            'name' => $input['name'],
            'email' => $input['email'],
            'password' => Hash::make($input['password']),
            'company_name' => $input['company_name'] ?? null,
            'free_checks_remaining' => config('fraud-detection.free_tier_limit', 100),
            'free_checks_reset_at' => now()->addMonth(),
        ]);

        // Create a default API key for the user
        $apiKeyData = \App\Models\ApiKey::generate($user, 'Default API Key');

        // Store the plain text secret temporarily for the response
        $user->initial_api_key = $apiKeyData['key'];
        $user->initial_api_secret = $apiKeyData['secret'];

        return $user;
    }
}
