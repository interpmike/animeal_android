package com.epmedu.animeal.login.profile.domain

import com.epmedu.animeal.login.profile.presentation.ui.UiText
import com.epmedu.animeal.resources.R

internal object FirstnameValidator : Validator {

    @Suppress("ReturnCount")
    override fun validate(value: String): ValidationResult {
        if (value.isBlank()) {
            return ValidationResult(
                isSuccess = false,
                errorMessage = UiText.StringResource(R.string.profile_name_blank_error_msg)
            )
        }
        if (value.length !in 2..35) {
            return ValidationResult(
                isSuccess = false,
                errorMessage = UiText.StringResource(R.string.profile_text_field_error_msg)
            )
        }
        return ValidationResult(isSuccess = true)
    }
}