<?php
/**
 * Project Company: GreenCode digital
 * Author: Stanislav Boyko <mzcoding@gmail.com>
 * Date: 23.01.2018
 */

namespace SailWithMe\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegisterRequest extends FormRequest
{
    public function authorize()
    {
        return false;
    }

    public function rules()
    {
        return [
            'email'            => 'required|email',
            'password'         => 'required|string|min:6|max:15',
            'gender'           => 'required',
            'adult'            => 'required',
            'alias'            => 'required',
            'is_adult'         => 'required|accepted',
            'policy_acception' => 'required|accepted',
        ];
    }
    public function messages()
    {
      return [
          'is_adult.required' => 'You must be at least 18 years old and accept projects policy!',
          'is_adult.accepted' => 'You must be at least 18 years old and accept projects policy!',
          'policy_acception.required' => 'You must be at least 18 years old and accept projects policy!',
          'policy_acception.accepted' => 'You must be at least 18 years old and accept projects policy!'
      ];
    }
}