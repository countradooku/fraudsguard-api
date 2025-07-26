<?php

// app/Http/Responses/LoginResponse.php

namespace App\Http\Responses;

use Illuminate\Http\JsonResponse;
use Laravel\Fortify\Contracts\LoginResponse as LoginResponseContract;
use Symfony\Component\HttpFoundation\Response;

class LoginResponse implements LoginResponseContract
{
    public function toResponse($request): JsonResponse|Response
    {
        $token = $request->user()->createToken('api-token')->plainTextToken;

        return response()->json([
            'two_factor' => false, // Or determine this dynamically if you use 2FA
            'token' => $token,
            'message' => 'Login successful',
        ]);
    }
}
