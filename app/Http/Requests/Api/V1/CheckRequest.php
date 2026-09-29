<?php

namespace App\Http\Requests\Api\V1;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

class CheckRequest extends FormRequest
{
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'product' => ['required', 'string', 'max:255'],
            'version' => ['required', 'string', 'max:255'],
            'vendor' => ['nullable', 'string', 'max:255'],
            'ecosystem' => ['nullable', 'string', 'max:255'],
        ];
    }
}
