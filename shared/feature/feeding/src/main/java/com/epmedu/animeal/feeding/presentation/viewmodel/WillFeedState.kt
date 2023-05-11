package com.epmedu.animeal.feeding.presentation.viewmodel

sealed interface WillFeedState {
    object Dismissed : WillFeedState
    object RequestingCameraPermission : WillFeedState
    object Showing : WillFeedState
}