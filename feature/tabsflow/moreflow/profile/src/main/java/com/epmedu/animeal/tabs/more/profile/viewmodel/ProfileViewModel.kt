package com.epmedu.animeal.tabs.more.profile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.epmedu.animeal.common.presentation.viewmodel.delegate.ActionDelegate
import com.epmedu.animeal.common.presentation.viewmodel.delegate.DefaultStateDelegate
import com.epmedu.animeal.common.presentation.viewmodel.delegate.StateDelegate
import com.epmedu.animeal.foundation.common.UiText
import com.epmedu.animeal.networkuser.domain.usecase.UpdateNetworkProfileUseCase
import com.epmedu.animeal.profile.data.model.Profile
import com.epmedu.animeal.profile.domain.GetProfileUseCase
import com.epmedu.animeal.profile.domain.SaveProfileUseCase
import com.epmedu.animeal.profile.presentation.viewmodel.ProfileInputFormState.FormState.EDITABLE
import com.epmedu.animeal.profile.presentation.viewmodel.ProfileInputFormState.FormState.EDITED
import com.epmedu.animeal.profile.presentation.viewmodel.ProfileInputFormState.FormState.READ_ONLY
import com.epmedu.animeal.profile.presentation.viewmodel.handler.ProfileInputFormHandler
import com.epmedu.animeal.tabs.more.profile.ProfileScreenEvent
import com.epmedu.animeal.tabs.more.profile.ProfileScreenEvent.Discard
import com.epmedu.animeal.tabs.more.profile.ProfileScreenEvent.Edit
import com.epmedu.animeal.tabs.more.profile.ProfileScreenEvent.InputFormEvent
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
    private val profileInputFormHandler: ProfileInputFormHandler,
    actionDelegate: ActionDelegate
) : ViewModel(),
    StateDelegate<ProfileState> by DefaultStateDelegate(ProfileState()),
    ActionDelegate by actionDelegate {

    private var lastSavedProfile = Profile()

    init {
        loadProfile()
        launchCheckingChanges()
        collectProfileInputFormState()
    }

    private fun loadProfile() {
        viewModelScope.launch {
            getProfileUseCase().collect {
                lastSavedProfile = it
                profileInputFormHandler.updateState { copy(profile = it, isAgeConfirmed = true) }
            }
        }
    }

    private fun launchCheckingChanges() {
        profileInputFormHandler.stateFlow.onEach {
            if (it.formState != READ_ONLY) {
                profileInputFormHandler.updateState {
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

    private fun collectProfileInputFormState() {
        viewModelScope.launch {
            profileInputFormHandler.stateFlow.collect {
                updateState { copy(profileInputFormState = it) }
            }
        }
    }

    fun handleScreenEvent(event: ProfileScreenEvent) {
        when (event) {
            is InputFormEvent -> {
                profileInputFormHandler.handleInputFormEvent(event.event)
            }

            is Edit -> {
                profileInputFormHandler.updateState { copy(formState = EDITABLE) }
            }

            is Discard -> {
                profileInputFormHandler.updateState {
                    copy(
                        profile = lastSavedProfile,
                        formState = READ_ONLY,
                        nameError = UiText.Empty,
                        surnameError = UiText.Empty,
                        emailError = UiText.Empty,
                    )
                }
            }

            is Save -> {
                if (profileInputFormHandler.state.hasErrors().not()) saveChanges()
            }
        }
    }

    private fun saveChanges() {
        viewModelScope.launch {
            with(profileInputFormHandler) {
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
}