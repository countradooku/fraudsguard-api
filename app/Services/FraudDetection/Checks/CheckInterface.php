<?php

namespace App\Services\FraudDetection\Checks;

interface CheckInterface
{
    /**
     * Determine if this check is applicable to the given data
     */
    public function applicable(array $data): bool;

    /**
     * Perform the fraud check
     */
    public function perform(array $data): array;
}
