<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Validator;

class RegisterRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'name'     => ['required', 'string', 'max:255'],
            'role'     => ['required', 'in:student,supervisor'],
            'email'    => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'string', 'min:8', 'confirmed'], // needs password_confirmation
            'code'     => ['required', 'string'],
        ];
    }

    public function after(): array
    {
        return [
            function (Validator $validator) {
                if ($validator->errors()->has('role') || $validator->errors()->has('code')) {
                    return;
                }

                $expected = config('gradtrack.registration_codes.' . $this->role);

                if (! $expected || ! hash_equals($expected, (string) $this->code)) {
                    $validator->errors()->add('code', 'Invalid registration code for this role.');
                }
            },
        ];
    }
}