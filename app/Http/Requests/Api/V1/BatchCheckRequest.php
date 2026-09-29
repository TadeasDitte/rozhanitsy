<?php

namespace App\Http\Requests\Api\V1;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

class BatchCheckRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'packages' => ['required', 'array', 'min:1', 'max:100'],
            'packages.*.product' => ['required', 'string', 'max:255'],
            'packages.*.version' => ['required', 'string', 'max:255'],
            'packages.*.vendor' => ['nullable', 'string', 'max:255'],
            'packages.*.ecosystem' => ['nullable', 'string', 'max:255'],
        ];
    }
}
