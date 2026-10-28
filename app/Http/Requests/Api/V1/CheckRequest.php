<?php

namespace App\Http\Requests\Api\V1;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class CheckRequest extends FormRequest
{
    /**
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'product' => ['required', 'string', 'max:255'],
            'version' => ['required', 'string', 'max:255'],
            'vendor' => ['nullable', 'string', 'max:255'],
            'ecosystem' => ['nullable', 'string', 'max:255'],
            'cvss_severity' => ['nullable', 'string', Rule::in(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])],
            'cvss_score' => ['nullable', 'numeric', 'between:0,10'],
            'include_low_confidence' => ['nullable', 'boolean'],
        ];
    }
}
