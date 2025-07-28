<?php

namespace App\Services\FraudDetection\Checks;

use App\Models\BlacklistedPhone;
use App\Services\HashingService;
use Illuminate\Support\Facades\Cache;
use libphonenumber\NumberParseException;
use libphonenumber\PhoneNumberType;
use libphonenumber\PhoneNumberUtil;

class PhoneCheck implements CheckInterface
{
    protected HashingService $hasher;

    protected PhoneNumberUtil $phoneUtil;

    public function __construct(HashingService $hasher)
    {
        $this->hasher = $hasher;
        $this->phoneUtil = PhoneNumberUtil::getInstance();
    }

    public function applicable(array $data): bool
    {
        return ! empty($data['phone']);
    }

    /**
     * @throws \Exception
     */
    public function perform(array $data): array
    {
        $phone = trim($data['phone']);
        $countryCode = $data['country'] ?? 'US'; // Default to US if not provided

        $details = [];
        $score = 0;
        $passed = true;

        // 1. Parse and validate phone number
        try {
            $phoneNumber = $this->phoneUtil->parse($phone, $countryCode);

            if (! $this->phoneUtil->isValidNumber($phoneNumber)) {
                return [
                    'passed' => false,
                    'score' => 100,
                    'details' => ['error' => 'Invalid phone number'],
                ];
            }

            $details['valid'] = true;
            $details['country_code'] = $phoneNumber->getCountryCode();
            $details['national_number'] = $phoneNumber->getNationalNumber();

        } catch (NumberParseException $e) {
            return [
                'passed' => false,
                'score' => 100,
                'details' => ['error' => 'Cannot parse phone number'],
            ];
        }

        // 2. Check if blacklisted
        if ($this->isBlacklisted($phone)) {
            $details['blacklisted'] = true;
            $score += 100;
            $passed = false;
        }

        // 3. Determine phone type
        $phoneType = $this->phoneUtil->getNumberType($phoneNumber);
        $typeString = $this->getPhoneTypeString($phoneType);
        $details['phone_type'] = $typeString;

        // Risk scoring based on phone type
        switch ($phoneType) {
            case PhoneNumberType::VOIP:
                $score += 40; // VOIP numbers higher risk
                break;
            case PhoneNumberType::TOLL_FREE:
                $score += 50; // Toll-free unusual for users
                break;
            case PhoneNumberType::PREMIUM_RATE:
                $score += 60; // Premium rate very suspicious
                break;
            case PhoneNumberType::SHARED_COST:
                $score += 30;
                break;
            case PhoneNumberType::MOBILE:
                // Mobile is normal, no additional risk
                break;
            case PhoneNumberType::FIXED_LINE:
                $score += 10; // Slightly higher risk than mobile
                break;
            case PhoneNumberType::UNKNOWN:
                $score += 20;
                break;
            case PhoneNumberType::PERSONAL_NUMBER:
            case PhoneNumberType::PAGER:
            case PhoneNumberType::UAN:
            case PhoneNumberType::EMERGENCY:
            case PhoneNumberType::VOICEMAIL:
            case PhoneNumberType::SHORT_CODE:
            case PhoneNumberType::FIXED_LINE_OR_MOBILE:
                throw new \Exception('To be implemented');
                break;
            case PhoneNumberType::STANDARD_RATE:
                throw new \Exception('To be implemented');
        }

        // 4. Check carrier information (if available)
        $carrierInfo = $this->getCarrierInfo($phoneNumber);
        if ($carrierInfo) {
            $details['carrier'] = $carrierInfo;

            // Check for known problematic carriers
            if ($this->isProblematicCarrier($carrierInfo['name'] ?? '')) {
                $score += 25;
            }
        }

        // 5. Geographic consistency check
        if (! empty($data['country'])) {
            $phoneCountry = $this->phoneUtil->getRegionCodeForNumber($phoneNumber);
            if ($phoneCountry !== $data['country']) {
                $details['country_mismatch'] = true;
                $score += 30;
            }
        }

        // 6. Format consistency check
        if ($this->hasInconsistentFormat($phone)) {
            $details['format_issues'] = true;
            $score += 15;
        }

        // 7. Velocity check
        $velocityCheck = $this->checkVelocity($phone);
        if ($velocityCheck) {
            $details['velocity'] = $velocityCheck;
            $score += $velocityCheck['risk_score'];
        }

        // 8. Check if disposable/temporary number
        if ($this->isDisposableNumber($phone)) {
            $details['disposable'] = true;
            $score += 50;
        }

        // Cap score at 100
        $score = min($score, 100);

        // If score is too high, mark as failed
        if ($score >= 80) {
            $passed = false;
        }

        return [
            'passed' => $passed,
            'score' => $score,
            'details' => $details,
        ];
    }

    protected function isBlacklisted(string $phone): bool
    {
        $hash = $this->hasher->hash($phone);

        return Cache::remember("blacklist:phone:{$hash}", 300, function () use ($hash) {
            return BlacklistedPhone::where('phone_hash', $hash)->exists();
        });
    }

    protected function getPhoneTypeString(PhoneNumberType $type): string
    {
        return match ($type) {
            PhoneNumberType::MOBILE => 'mobile',
            PhoneNumberType::FIXED_LINE => 'landline',
            PhoneNumberType::FIXED_LINE_OR_MOBILE => 'fixed_or_mobile',
            PhoneNumberType::TOLL_FREE => 'toll_free',
            PhoneNumberType::PREMIUM_RATE => 'premium_rate',
            PhoneNumberType::SHARED_COST => 'shared_cost',
            PhoneNumberType::VOIP => 'voip',
            PhoneNumberType::PERSONAL_NUMBER => 'personal',
            PhoneNumberType::PAGER => 'pager',
            PhoneNumberType::UAN => 'uan',
            PhoneNumberType::VOICEMAIL => 'voicemail',
            default => 'unknown',
        };
    }

    protected function getCarrierInfo($phoneNumber): ?array
    {
        // In production, you would use a service like:
        // - Twilio Lookup API
        // - Numverify API
        // - Truecaller API

        // For now, return null
        return null;
    }

    protected function isProblematicCarrier(string $carrierName): bool
    {
        $problematicCarriers = [
            // List of carriers known for easy SIM card acquisition
            // or high fraud rates
        ];

        $carrierLower = strtolower($carrierName);
        foreach ($problematicCarriers as $problematic) {
            if (str_contains($carrierLower, strtolower($problematic))) {
                return true;
            }
        }

        return false;
    }

    protected function hasInconsistentFormat(string $phone): bool
    {
        // Check for weird formatting that might indicate fake numbers
        // Too many special characters
        $specialChars = preg_match_all('/[^0-9+\s\-().]/', $phone);
        if ($specialChars > 2) {
            return true;
        }

        // Repeating patterns (like 1234567890, 1111111111)
        if (preg_match('/(\d)\1{6,}/', preg_replace('/\D/', '', $phone))) {
            return true;
        }

        // Sequential patterns
        $digits = preg_replace('/\D/', '', $phone);
        if (preg_match('/(?:0123|1234|2345|3456|4567|5678|6789|7890)/', $digits)) {
            return true;
        }

        return false;
    }

    protected function checkVelocity(string $phone): ?array
    {
        $hash = $this->hasher->hash($phone);
        $key = "velocity:phone:{$hash}";

        // Count uses in last hour
        $hourKey = $key.':hour:'.date('YmdH');
        $hourCount = Cache::increment($hourKey, 1);
        Cache::remember($hourKey, 3600, function () {
            return 0;
        });

        // Count uses in last day
        $dayKey = $key.':day:'.date('Ymd');
        $dayCount = Cache::increment($dayKey, 1);
        Cache::remember($dayKey, 86400, function () {
            return 0;
        });

        $riskScore = 0;
        $details = [
            'uses_per_hour' => $hourCount,
            'uses_per_day' => $dayCount,
        ];

        // Calculate risk based on velocity
        if ($hourCount > 2) {
            $riskScore += 15;
        }
        if ($hourCount > 5) {
            $riskScore += 25;
        }
        if ($dayCount > 10) {
            $riskScore += 20;
        }

        $details['risk_score'] = $riskScore;

        return $details;
    }

    protected function isDisposableNumber(string $phone): bool
    {
        // Known prefixes for disposable/temporary number services
        $disposablePrefixes = [
            // US temporary number services
            '+1555', // Example prefix
            // Add more known disposable number prefixes
        ];

        foreach ($disposablePrefixes as $prefix) {
            if (str_starts_with($phone, $prefix)) {
                return true;
            }
        }

        // Check against known VOIP/temporary number providers
        // In production, you'd maintain a database of these

        return false;
    }
}
