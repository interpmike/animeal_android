package com.epmedu.animeal.debugmenu.presentation.ui

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material.DrawerValue
import androidx.compose.material.ModalDrawer
import androidx.compose.material.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import com.epmedu.animeal.common.route.MainRoute
import com.epmedu.animeal.debugmenu.presentation.DebugMenuScreenEvent
import com.epmedu.animeal.debugmenu.presentation.DebugMenuScreenEvent.ResetGeolocationPermissionRequestedAgain
import com.epmedu.animeal.debugmenu.presentation.DebugMenuScreenEvent.SetFinishProfileAsStartDestination
import com.epmedu.animeal.debugmenu.presentation.DebugMenuScreenEvent.SwitchUsingMockedFeedingPoints
import com.epmedu.animeal.debugmenu.presentation.viewmodel.DebugMenuState
import com.epmedu.animeal.foundation.dialog.AnimealQuestionDialog
import com.epmedu.animeal.foundation.theme.AnimealTheme
import kotlinx.coroutines.launch

@Composable
internal fun DebugMenuContent(
    state: DebugMenuState,
    initialState: DrawerValue = DrawerValue.Closed,
    onNavigate: (MainRoute) -> Unit,
    onEvent: (DebugMenuScreenEvent) -> Unit,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val drawerState = rememberDrawerState(initialValue = initialState)
    var showRestartDialog by remember { mutableStateOf(false) }

    val menuItems = listOf(
        DebugMenuItem.Switch(
            title = "Use mocked feeding points",
            checkedInitially = state.useMockedFeedingPoints,
            onCheckedChange = {
                showRestartDialog = true
                onEvent(SwitchUsingMockedFeedingPoints(it))
            }
        ),
        DebugMenuItem.Divider,
        DebugMenuItem.Button(
            title = "Open Splash Screen",
            onClick = { onNavigate(MainRoute.Splash) }
        ),
        DebugMenuItem.Button(
            title = "Open SignUpFlow",
            onClick = { onNavigate(MainRoute.SignUp) }
        ),
        DebugMenuItem.Button(
            title = "Open FinishProfileScreen",
            onClick = {
                onEvent(SetFinishProfileAsStartDestination)
                onNavigate(MainRoute.SignUp)
            }
        ),
        DebugMenuItem.Button(
            title = "Open TabsFlow",
            onClick = { onNavigate(MainRoute.Tabs) }
        ),
        DebugMenuItem.Button(
            title = "Reset Geolocation Permission Requested Again",
            onClick = { onEvent(ResetGeolocationPermissionRequestedAgain) }
        ),
        DebugMenuItem.Button(
            title = "Restart App",
            onClick = {
                restartApp(context)
            }
        )
    )

    Box(modifier = Modifier.fillMaxSize()) {
        ModalDrawer(
            drawerContent = {
                DebugMenuColumn(menuItems = menuItems)
            },
            modifier = Modifier.statusBarsPadding(),
            gesturesEnabled = drawerState.isOpen,
            drawerState = drawerState,
            drawerShape = RectangleShape
        ) {
            content()
        }
        DebugMenuIconButton(
            onClick = {
                scope.launch {
                    when {
                        drawerState.isClosed -> drawerState.open()
                        else -> drawerState.close()
                    }
                }
            },
            modifier = Modifier
                .statusBarsPadding()
                .align(Alignment.TopEnd)
        )
    }

    if (showRestartDialog) {
        AnimealQuestionDialog(
            title = "App has to be restarted to apply changes",
            acceptText = "Restart",
            dismissText = "Cancel",
            onConfirm = {
                showRestartDialog = false
                restartApp(context)
            },
            onDismiss = {
                showRestartDialog = false
            }
        )
    }
}

private fun restartApp(context: Context) {
    val packageManager: PackageManager = context.packageManager
    val intent: Intent = packageManager.getLaunchIntentForPackage(context.packageName)!!
    val componentName: ComponentName = intent.component!!
    val restartIntent: Intent = Intent.makeRestartActivityTask(componentName)
    context.startActivity(restartIntent)
    Runtime.getRuntime().exit(0)
}

@Preview
@Composable
private fun DebugMenuContentPreview() {
    AnimealTheme {
        DebugMenuContent(
            state = DebugMenuState(useMockedFeedingPoints = false),
            initialState = DrawerValue.Open,
            onNavigate = {},
            onEvent = {},
            content = {}
        )
    }
}