<?php

namespace App\Services\FraudDetection\Checks;

use App\Models\BlacklistedCreditCard;
use App\Services\HashingService;
use Illuminate\Support\Facades\Cache;

class CreditCardCheck implements CheckInterface
{
    protected HashingService $hasher;

    protected array $cardPatterns = [
        'visa' => '/^4[0-9]{12}(?:[0-9]{3})?$/',
        'mastercard' => '/^5[1-5][0-9]{14}$|^2(?:2(?:2[1-9]|[3-9][0-9])|[3-6][0-9][0-9]|7(?:[01][0-9]|20))[0-9]{12}$/',
        'amex' => '/^3[47][0-9]{13}$/',
        'discover' => '/^6(?:011|5[0-9]{2})[0-9]{12}$/',
        'jcb' => '/^(?:2131|1800|35\d{3})\d{11}$/',
        'diners' => '/^3(?:0[0-5]|[68][0-9])[0-9]{11}$/',
        'maestro' => '/^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$/',
    ];

    public function __construct(HashingService $hasher)
    {
        $this->hasher = $hasher;
    }

    public function applicable(array $data): bool
    {
        return ! empty($data['credit_card']);
    }

    public function perform(array $data): array
    {
        $creditCard = preg_replace('/[^0-9]/', '', $data['credit_card']);
        $details = [];
        $score = 0;
        $passed = true;

        // 1. Basic format validation
        if (! $this->isValidFormat($creditCard)) {
            return [
                'passed' => false,
                'score' => 100,
                'details' => ['error' => 'Invalid credit card format'],
            ];
        }

        // 2. Luhn algorithm check
        if (! $this->passesLuhnCheck($creditCard)) {
            $details['luhn_check'] = 'failed';
            $score += 100;
            $passed = false;

            return [
                'passed' => $passed,
                'score' => $score,
                'details' => $details,
            ];
        }
        $details['luhn_check'] = 'passed';

        // 3. Identify card type
        $cardType = $this->identifyCardType($creditCard);
        $details['card_type'] = $cardType ?: 'unknown';

        if (! $cardType) {
            $score += 30; // Unknown card type
        }

        // 4. Check if blacklisted
        if ($this->isBlacklisted($creditCard)) {
            $details['blacklisted'] = true;
            $score += 100;
            $passed = false;
        }

        // 5. Check for test card numbers
        if ($this->isTestCard($creditCard)) {
            $details['test_card'] = true;
            $score += 80;
            $passed = false;
        }

        // 6. BIN (Bank Identification Number) check
        $binCheck = $this->checkBIN($creditCard);
        if ($binCheck) {
            $details['bin_check'] = $binCheck;
            $score += $binCheck['risk_score'];
        }

        // 7. Velocity check (multiple uses)
        $velocityCheck = $this->checkVelocity($creditCard);
        if ($velocityCheck) {
            $details['velocity'] = $velocityCheck;
            $score += $velocityCheck['risk_score'];
        }

        // 8. Check card age (if available from BIN data)
        if (isset($binCheck['card_age_months']) && $binCheck['card_age_months'] < 3) {
            $details['new_card'] = true;
            $score += 20;
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

    protected function isValidFormat(string $creditCard): bool
    {
        // Check length (most cards are 13-19 digits)
        $length = strlen($creditCard);
        if ($length < 13 || $length > 19) {
            return false;
        }

        // Must be all digits
        if (! ctype_digit($creditCard)) {
            return false;
        }

        return true;
    }

    protected function passesLuhnCheck(string $creditCard): bool
    {
        $sum = 0;
        $numDigits = strlen($creditCard);
        $parity = $numDigits % 2;

        for ($i = 0; $i < $numDigits; $i++) {
            $digit = (int) $creditCard[$i];

            if ($i % 2 == $parity) {
                $digit *= 2;
                if ($digit > 9) {
                    $digit -= 9;
                }
            }

            $sum += $digit;
        }

        return ($sum % 10) == 0;
    }

    protected function identifyCardType(string $creditCard): ?string
    {
        foreach ($this->cardPatterns as $type => $pattern) {
            if (preg_match($pattern, $creditCard)) {
                return $type;
            }
        }

        return null;
    }

    protected function isBlacklisted(string $creditCard): bool
    {
        $hash = $this->hasher->hash($creditCard);

        return Cache::remember("blacklist:card:{$hash}", 300, function () use ($hash) {
            return BlacklistedCreditCard::where('card_hash', $hash)->exists();
        });
    }

    protected function isTestCard(string $creditCard): bool
    {
        // Common test card numbers
        $testCards = [
            '4111111111111111', // Visa test
            '4012888888881881', // Visa test
            '5555555555554444', // Mastercard test
            '5105105105105100', // Mastercard test
            '378282246310005',  // Amex test
            '371449635398431',  // Amex test
            '6011111111111117', // Discover test
            '6011000990139424', // Discover test
            '3056930009020004', // Diners test
            '3566002020360505', // JCB test
            '4000000000000002', // Stripe test - decline
            '4242424242424242', // Stripe test - success
        ];

        return in_array($creditCard, $testCards);
    }

    protected function checkBIN(string $creditCard): ?array
    {
        // BIN is first 6 digits
        $bin = substr($creditCard, 0, 6);

        // In production, you would query a BIN database or API
        // Services like BinList.net, BinTable.com, or maintain your own

        // For now, return basic risk assessment based on card type
        $cardType = $this->identifyCardType($creditCard);

        $riskScore = 0;
        $details = [
            'bin' => $bin,
            'card_brand' => $cardType,
        ];

        // Prepaid cards often have higher fraud risk
        if ($this->isPrepaidBIN($bin)) {
            $details['card_subtype'] = 'prepaid';
            $riskScore += 30;
        }

        // Virtual cards
        if ($this->isVirtualCardBIN($bin)) {
            $details['card_subtype'] = 'virtual';
            $riskScore += 20;
        }

        $details['risk_score'] = $riskScore;

        return $details;
    }

    protected function isPrepaidBIN(string $bin): bool
    {
        // Known prepaid BINs (simplified list)
        $prepaidBins = [
            '440393', '440394', '440395', // Some prepaid Visa
            '516730', '516731', '516732', // Some prepaid Mastercard
        ];

        return in_array($bin, $prepaidBins);
    }

    protected function isVirtualCardBIN(string $bin): bool
    {
        // Known virtual card BINs (simplified list)
        $virtualBins = [
            '400000', // Some virtual card providers
            '453091', // Capital One Eno
        ];

        foreach ($virtualBins as $vBin) {
            if (str_starts_with($bin, $vBin)) {
                return true;
            }
        }

        return false;
    }

    protected function checkVelocity(string $creditCard): ?array
    {
        $hash = $this->hasher->hash($creditCard);
        $key = "velocity:card:{$hash}";

        // Count uses in last hour
        $hourKey = $key.':hour:'.date('YmdH');
        $hourCount = Cache::increment($hourKey, 1);
        Cache::remember($hourKey, 3600, function () {
            return 1; // Initialize if not set
        });

        // Count uses in last day
        $dayKey = $key.':day:'.date('Ymd');
        $dayCount = Cache::increment($dayKey, 1);
        Cache::remember($dayKey, 86400, function () {
            return 1; // Initialize if not set
        });

        $riskScore = 0;
        $details = [
            'uses_per_hour' => $hourCount,
            'uses_per_day' => $dayCount,
        ];

        // Calculate risk based on velocity
        if ($hourCount > 3) {
            $riskScore += 20;
        }
        if ($hourCount > 10) {
            $riskScore += 30;
        }
        if ($dayCount > 20) {
            $riskScore += 25;
        }

        $details['risk_score'] = $riskScore;

        return $details;
    }
}
