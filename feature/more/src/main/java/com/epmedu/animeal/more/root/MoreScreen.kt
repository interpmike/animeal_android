package com.epmedu.animeal.more.root

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.hilt.navigation.compose.hiltViewModel
import com.epmedu.animeal.extensions.currentOrThrow
import com.epmedu.animeal.foundation.bottombar.BottomBarVisibility
import com.epmedu.animeal.foundation.bottombar.BottomBarVisibilityState.SHOWN
import com.epmedu.animeal.more.MoreViewModel
import com.epmedu.animeal.more.MoreViewModel.Event
import com.epmedu.animeal.navigation.navigator.LocalNavigator
import com.epmedu.animeal.navigation.route.MainRoute

@Composable
internal fun MoreScreen() {
    val viewModel: MoreViewModel = hiltViewModel()
    val navigator = LocalNavigator.currentOrThrow

    BottomBarVisibility(SHOWN)

    LaunchedEffect(Unit) {
        viewModel.events.collect {
            if (it is Event.NavigateToOnboarding) {
                navigator.parent?.parent?.navigate(MainRoute.SignUp.name) {
                    popUpTo(MainRoute.Tabs.name) {
                        inclusive = true
                    }
                }
            }
        }
    }

    MoreScreenUi(
        onNavigate = navigator::navigate,
    )
}
