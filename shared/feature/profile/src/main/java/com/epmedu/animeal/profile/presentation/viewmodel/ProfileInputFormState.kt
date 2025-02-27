package com.epmedu.animeal.profile.presentation.viewmodel

import com.epmedu.animeal.foundation.common.UiText
import com.epmedu.animeal.profile.data.model.Profile
import com.epmedu.animeal.profile.domain.model.getFormat

data class ProfileInputFormState(
    val profile: Profile = Profile(),
    val isAgeConfirmed: Boolean = false,
    val formState: FormState = FormState.READ_ONLY,
    val isCountrySelectorClickable: Boolean = false,
    val isPhoneNumberEnabled: Boolean = false,
    val isAgeConfirmationEnabled: Boolean = false,
    val nameError: UiText = UiText.Empty,
    val surnameError: UiText = UiText.Empty,
    val emailError: UiText = UiText.Empty,
    val phoneNumberError: UiText = UiText.Empty
) {
    val region = profile.phoneNumberRegion
    val phoneNumberDigitsCount = profile.phoneNumberRegion.phoneNumberDigitsCount

    val phoneNumber: String
        get() = profile.phoneNumber.replace("\\D".toRegex(), "")

    val prefix: String
        get() {
            return profile.phoneNumberRegion.phoneNumberCode
        }
    val format: String
        get() {
            return profile.phoneNumberRegion.getFormat()
        }
    val numberLength: Int
        get() {
            return profile.phoneNumberRegion.phoneNumberDigitsCount.last()
        }

    fun hasErrors() =
        listOf(
            nameError,
            surnameError,
            emailError,
            phoneNumberError
        ).any { it !is UiText.Empty } || isAgeConfirmed.not()

    fun isEditedOrHasErrors() = formState == FormState.EDITED || hasErrors()

    enum class FormState {
        READ_ONLY,
        EDITABLE,
        EDITED
    }
}