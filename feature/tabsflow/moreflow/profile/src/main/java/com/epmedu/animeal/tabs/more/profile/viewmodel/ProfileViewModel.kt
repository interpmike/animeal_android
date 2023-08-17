package com.epmedu.animeal.tabs.more.profile.viewmodel

import androidx.lifecycle.viewModelScope
import com.epmedu.animeal.common.presentation.viewmodel.delegate.ActionDelegate
import com.epmedu.animeal.common.presentation.viewmodel.delegate.DefaultStateDelegate
import com.epmedu.animeal.networkuser.domain.usecase.UpdateNetworkProfileUseCase
import com.epmedu.animeal.profile.data.model.Profile
import com.epmedu.animeal.profile.domain.GetProfileUseCase
import com.epmedu.animeal.profile.domain.SaveProfileUseCase
import com.epmedu.animeal.profile.domain.ValidateBirthDateUseCase
import com.epmedu.animeal.profile.domain.ValidateEmailUseCase
import com.epmedu.animeal.profile.domain.ValidateNameUseCase
import com.epmedu.animeal.profile.domain.ValidateSurnameUseCase
import com.epmedu.animeal.profile.presentation.ProfileInputFormEvent.PhoneNumberChanged
import com.epmedu.animeal.profile.presentation.viewmodel.BaseProfileViewModel
import com.epmedu.animeal.profile.presentation.viewmodel.ProfileState
import com.epmedu.animeal.profile.presentation.viewmodel.ProfileState.FormState.EDITABLE
import com.epmedu.animeal.profile.presentation.viewmodel.ProfileState.FormState.EDITED
import com.epmedu.animeal.profile.presentation.viewmodel.ProfileState.FormState.READ_ONLY
import com.epmedu.animeal.tabs.more.profile.ProfileScreenEvent
import com.epmedu.animeal.tabs.more.profile.ProfileScreenEvent.Discard
import com.epmedu.animeal.tabs.more.profile.ProfileScreenEvent.Edit
import com.epmedu.animeal.tabs.more.profile.ProfileScreenEvent.Save
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
internal class ProfileViewModel @Inject constructor(
    private val getProfileUseCase: GetProfileUseCase,
    private val saveProfileUseCase: SaveProfileUseCase,
    private val updateNetworkProfileUseCase: UpdateNetworkProfileUseCase,
    validateNameUseCase: ValidateNameUseCase,
    validateSurnameUseCase: ValidateSurnameUseCase,
    validateEmailUseCase: ValidateEmailUseCase,
    validateBirthDateUseCase: ValidateBirthDateUseCase,
    actionDelegate: ActionDelegate
) : BaseProfileViewModel(
    stateDelegate = DefaultStateDelegate(ProfileState()),
    validateNameUseCase = validateNameUseCase,
    validateSurnameUseCase = validateSurnameUseCase,
    validateEmailUseCase = validateEmailUseCase,
    validateBirthDateUseCase = validateBirthDateUseCase
),
    ActionDelegate by actionDelegate {

    private var lastSavedProfile = Profile()

    init {
        loadProfile()
        launchCheckingChanges()
    }

    private fun loadProfile() {
        viewModelScope.launch {
            getProfileUseCase().collect {
                lastSavedProfile = it
                updateState { copy(profile = it) }
            }
        }
    }

    private fun launchCheckingChanges() {
        stateFlow.onEach {
            if (it.formState != READ_ONLY) {
                updateState {
                    copy(
                        formState = when {
                            it.hasErrors() || it.profile == lastSavedProfile -> EDITABLE
                            else -> EDITED
                        }
                    )
                }
            }
        }.launchIn(viewModelScope)
    }

    override fun handlePhoneNumberChangedEvent(event: PhoneNumberChanged) {
        /* Do nothing since phone number is immutable */
    }

    fun handleScreenEvent(event: ProfileScreenEvent) {
        when (event) {
            is Edit -> {
                updateState { copy(formState = EDITABLE) }
            }
            is Discard -> {
                updateState { ProfileState(profile = lastSavedProfile) }
            }
            is Save -> {
                saveChanges()
            }
        }
    }

    private fun saveChanges() {
        viewModelScope.launch {
            saveProfileUseCase(state.profile).collectLatest {
                performAction(
                    action = { updateNetworkProfileUseCase(state.profile) },
                    onSuccess = {
                        lastSavedProfile = state.profile
                        updateState { copy(formState = READ_ONLY) }
                    }
                )
            }
        }
    }
}