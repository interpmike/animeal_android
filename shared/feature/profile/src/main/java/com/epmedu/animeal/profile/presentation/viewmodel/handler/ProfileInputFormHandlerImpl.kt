package com.epmedu.animeal.profile.presentation.viewmodel.handler

import com.epmedu.animeal.common.presentation.viewmodel.delegate.DefaultStateDelegate
import com.epmedu.animeal.common.presentation.viewmodel.delegate.StateDelegate
import com.epmedu.animeal.foundation.common.UiText
import com.epmedu.animeal.profile.domain.ValidateEmailUseCase
import com.epmedu.animeal.profile.domain.ValidateNameUseCase
import com.epmedu.animeal.profile.domain.ValidatePhoneNumberUseCase
import com.epmedu.animeal.profile.domain.ValidateSurnameUseCase
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.AgeConfirmationChanged
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.EmailChanged
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.EmailFocusCleared
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.NameChanged
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.NameFocusCleared
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.PhoneNumberChanged
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.PhoneNumberFocusCleared
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.RegionChanged
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.SurnameChanged
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.SurnameFocusCleared
import com.epmedu.animeal.profile.presentation.viewmodel.ProfileInputFormState

class ProfileInputFormHandlerImpl(
    private val validateNameUseCase: ValidateNameUseCase,
    private val validateSurnameUseCase: ValidateSurnameUseCase,
    private val validateEmailUseCase: ValidateEmailUseCase,
    private val validatePhoneNumberUseCase: ValidatePhoneNumberUseCase
) : ProfileInputFormHandler,
    StateDelegate<ProfileInputFormState> by DefaultStateDelegate(initialState = ProfileInputFormState()) {

    override fun handleInputFormEvent(event: ProfileInputFormEvent) {
        when (event) {
            is NameChanged -> handleNameChangedEvent(event)
            is SurnameChanged -> handleSurnameChangedEvent(event)
            is EmailChanged -> handleEmailChangedEvent(event)
            is PhoneNumberChanged -> handlePhoneNumberChangedEvent(event)
            is RegionChanged -> handleRegionChangedEvent(event)
            is AgeConfirmationChanged -> handleAgeConfirmationChangedEvent(event)
            is NameFocusCleared -> validateName()
            is SurnameFocusCleared -> validateSurname()
            is EmailFocusCleared -> validateEmail()
            is PhoneNumberFocusCleared -> validatePhoneNumber()
        }
    }

    private fun handleNameChangedEvent(event: NameChanged) {
        updateState {
            copy(
                profile = profile.copy(name = event.name),
                nameError = UiText.Empty
            )
        }
    }

    private fun handleSurnameChangedEvent(event: SurnameChanged) {
        updateState {
            copy(
                profile = profile.copy(surname = event.surname),
                surnameError = UiText.Empty
            )
        }
    }

    private fun handleEmailChangedEvent(event: EmailChanged) {
        updateState {
            copy(
                profile = profile.copy(email = event.email),
                emailError = UiText.Empty
            )
        }
    }

    private fun handlePhoneNumberChangedEvent(event: PhoneNumberChanged) {
        updateState {
            copy(
                profile = profile.copy(phoneNumber = event.phoneNumber),
                phoneNumberError = UiText.Empty
            )
        }
    }

    private fun handleRegionChangedEvent(event: RegionChanged) {
        updateState {
            copy(
                profile = profile.copy(phoneNumberRegion = event.region, phoneNumber = ""),
            )
        }
    }

    private fun handleAgeConfirmationChangedEvent(event: AgeConfirmationChanged) {
        updateState {
            copy(
                isAgeConfirmed = event.isConfirmed
            )
        }
    }

    private fun validateName() {
        updateState {
            copy(
                nameError = validateNameUseCase(profile.name)
            )
        }
    }

    private fun validateSurname() {
        updateState {
            copy(
                surnameError = validateSurnameUseCase(profile.surname)
            )
        }
    }

    private fun validateEmail() {
        updateState {
            copy(
                emailError = validateEmailUseCase(profile.email)
            )
        }
    }

    private fun validatePhoneNumber() {
        updateState {
            copy(
                phoneNumberError = validatePhoneNumberUseCase(
                    phoneNumber,
                    phoneNumberDigitsCount
                )
            )
        }
    }
}
