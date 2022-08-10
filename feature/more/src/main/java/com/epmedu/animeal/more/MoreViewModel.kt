package com.epmedu.animeal.more

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.epmedu.animeal.common.data.repository.ProfileRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
internal class MoreViewModel @Inject constructor(
    private val profileRepository: ProfileRepository
) : ViewModel() {

    private val _event = MutableSharedFlow<Event>()
    val event: SharedFlow<Event> get() = _event.asSharedFlow()

    internal fun logout() {
        viewModelScope.launch {
            profileRepository.clearProfile()
            _event.emit(Event.NavigateToOnboarding)
        }
    }

    sealed interface Event {
        object NavigateToOnboarding : Event
    }
}