package com.epmedu.animeal.login.domain

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.epmedu.animeal.login.domain.model.EnterCodeScreenModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

internal class EnterCodeViewModel : ViewModel() {

    private val _model = MutableStateFlow(
        EnterCodeScreenModel(
            phoneNumber = getPhoneNumber(),
            code = getEmptyCode(),
        )
    )
    val model: StateFlow<EnterCodeScreenModel> = _model.asStateFlow()
    private val _isCodeCorrect = MutableStateFlow(false)
    val isCodeCorrect: StateFlow<Boolean> get() = _isCodeCorrect.asStateFlow()

    private val currentModel get() = _model.value

    init {
        viewModelScope.launch {
            launchResendTimer()
        }
    }

    private fun getPhoneNumber(): String {
        // TODO: Retrieve a phone number from repository
        return PHONE_NUMBER_PLACEHOLDER
    }

    private fun getEmptyCode() = List(CODE_SIZE) { null }

    private suspend fun launchResendTimer() {
        for (tick in RESEND_DELAY downTo 1L) {
            _model.emit(currentModel.copy(resendDelay = tick))
            delay(1000)
        }
        _model.emit(currentModel.copy(isResendEnabled = true, resendDelay = 0))
    }

    internal fun resendCode() {
        viewModelScope.launch {
            clearCodeAndDisableResend()
            launchResendTimer()
        }
    }

    private suspend fun clearCodeAndDisableResend() {
        _model.emit(currentModel.copy(code = getEmptyCode(), isResendEnabled = false))
    }

    internal fun changeDigit(position: Int, digit: Int?) {
        viewModelScope.launch {
            _model.emit(
                currentModel.copy(
                    code = getNewCodeWithReplacedDigit(position, digit)
                )
            )
            validateCodeIfFull()
        }
    }

    private fun getNewCodeWithReplacedDigit(position: Int, newDigit: Int?): List<Int?> {
        return currentModel.code.mapIndexed { index, currentDigit ->
            if (index == position) newDigit
            else currentDigit
        }
    }

    private suspend fun validateCodeIfFull() {
        if (currentModel.code.all { it != null }) {
            _model.emit(currentModel.copy(isError = isCodeWrong()))
            _isCodeCorrect.emit(isCodeCorrect())
        }
    }

    private fun isCodeWrong() = !isCodeCorrect()

    private fun isCodeCorrect(): Boolean {
        val codeString = currentModel.code.joinToString("")
        return codeString == CORRECT_CODE
    }

    internal companion object {
        internal const val CODE_SIZE = 4
        internal const val RESEND_DELAY = 30L
        internal const val PHONE_NUMBER_PLACEHOLDER = "558 49-99-69"

        private const val CORRECT_CODE = "1111"
    }
}