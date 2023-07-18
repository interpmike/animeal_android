package com.epmedu.animeal.signup.finishprofile.presentation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.focus.FocusRequester
import androidx.hilt.navigation.compose.hiltViewModel
import com.epmedu.animeal.common.route.MainRoute
import com.epmedu.animeal.common.route.SignUpRoute
import com.epmedu.animeal.extensions.currentOrThrow
import com.epmedu.animeal.navigation.navigator.LocalNavigator
import com.epmedu.animeal.navigation.navigator.Navigator
import com.epmedu.animeal.network.NetworkState
import com.epmedu.animeal.signup.finishprofile.presentation.FinishProfileScreenEvent.Cancel
import com.epmedu.animeal.signup.finishprofile.presentation.FinishProfileScreenEvent.Submit
import com.epmedu.animeal.signup.finishprofile.presentation.viewmodel.FinishProfileEvent
import com.epmedu.animeal.signup.finishprofile.presentation.viewmodel.FinishProfileViewModel

@Composable
fun FinishProfileScreen() {
    val viewModel: FinishProfileViewModel = hiltViewModel()
    val navigator = LocalNavigator.currentOrThrow
    val state by viewModel.stateFlow.collectAsState()
    val focusRequester = remember { FocusRequester() }

    if (state.networkState == NetworkState.Lost) {
        navigator.popBackStackOrNavigate(SignUpRoute.Onboarding.name)
    }

    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
        viewModel.events.collect {
            when (it) {
                FinishProfileEvent.NavigateBackToOnboarding -> {
                    navigator.popBackStackOrNavigate(SignUpRoute.Onboarding.name)
                }
                FinishProfileEvent.ProfileFinished -> {
                    navigator.navigateToTabs()
                }
                FinishProfileEvent.NavigateToConfirmPhone -> {
                    navigator.navigate(SignUpRoute.EnterCode.name)
                }
            }
        }
    }

    FinishProfileScreenUI(
        state = state,
        focusRequester = focusRequester,
        onCancel = { viewModel.handleScreenEvents(Cancel) },
        onDone = { viewModel.handleScreenEvents(Submit) },
        onInputFormEvent = viewModel::handleInputFormEvent
    )
}

private fun Navigator.navigateToTabs() {
    parent?.navigate(MainRoute.Tabs.name) {
        popUpTo(MainRoute.SignUp.name) {
            inclusive = true
        }
    }
}