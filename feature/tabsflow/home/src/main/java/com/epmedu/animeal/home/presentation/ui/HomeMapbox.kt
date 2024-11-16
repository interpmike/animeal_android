package com.epmedu.animeal.home.presentation.ui

import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.epmedu.animeal.extensions.formatMetersToKilometers
import com.epmedu.animeal.extensions.formatNumberToHourMin
import com.epmedu.animeal.feeding.domain.model.FeedingConfirmationState.Showing
import com.epmedu.animeal.feeding.presentation.model.FeedingPointModel
import com.epmedu.animeal.feeding.presentation.model.MapLocation
import com.epmedu.animeal.foundation.bottomsheet.AnimealBottomSheetState
import com.epmedu.animeal.foundation.tabs.AnimealSwitch
import com.epmedu.animeal.foundation.tabs.model.AnimalType
import com.epmedu.animeal.foundation.theme.bottomBarHeight
import com.epmedu.animeal.foundation.theme.bottomBarPadding
import com.epmedu.animeal.geolocation.gpssetting.GpsSettingState
import com.epmedu.animeal.home.presentation.ui.map.GesturesListeners
import com.epmedu.animeal.home.presentation.ui.map.MapBoxInitOptions
import com.epmedu.animeal.home.presentation.ui.map.MapUiSettings
import com.epmedu.animeal.home.presentation.ui.map.MarkerController
import com.epmedu.animeal.home.presentation.ui.map.RouteTopBar
import com.epmedu.animeal.home.presentation.ui.map.RouteView
import com.epmedu.animeal.home.presentation.ui.map.rememberMapInitOptions
import com.epmedu.animeal.home.presentation.ui.map.rememberMapUiSettings
import com.epmedu.animeal.home.presentation.ui.map.rememberMapViewWithLifecycle
import com.epmedu.animeal.home.presentation.ui.map.setLocation
import com.epmedu.animeal.home.presentation.ui.map.setLocationOnRoute
import com.epmedu.animeal.home.presentation.viewmodel.HomeState
import com.epmedu.animeal.home.presentation.viewmodel.LocationState
import com.epmedu.animeal.permissions.presentation.PermissionStatus
import com.epmedu.animeal.resources.R
import com.epmedu.animeal.router.model.RouteResult
import com.epmedu.animeal.router.presentation.FeedingRouteState
import com.epmedu.animeal.timer.data.model.TimerState
import com.mapbox.geojson.Point
import com.mapbox.maps.CameraOptions
import com.mapbox.maps.MapView
import com.mapbox.maps.StyleLoadedCallback
import com.mapbox.maps.plugin.attribution.attribution
import com.mapbox.maps.plugin.logo.logo
import kotlin.math.max

@Composable
internal fun HomeMapbox(
    state: HomeState,
    bottomSheetState: AnimealBottomSheetState,
    onFeedingPointSelect: (point: FeedingPointModel) -> Unit,
    onGeolocationClick: (MapView) -> Unit,
    onFeedingsClick: () -> Unit,
    onInitialLocationDisplay: () -> Unit,
    onRouteResult: (result: RouteResult) -> Unit,
    onCancelRouteClick: () -> Unit,
    onCameraChange: () -> Unit,
    onMapClick: (Point) -> Unit,
    onSelectTab: (AnimalType) -> Unit
) {
    val context = LocalContext.current

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val mapboxMapView = rememberMapboxMapView(homeState = state)

        mapboxMapView.LogoAndAttributionMarginsEffect(
            maxHeight = maxHeight,
            bottomSheetState = bottomSheetState
        )

        /** Show user location after successful feeding operation */
        if (state.feedState.feedingConfirmationState is Showing) {
            ShowUserCurrentLocation(state, mapboxMapView)
        }

        MapboxMap(
            mapboxMapView = mapboxMapView,
            state = state,
            onFeedingPointClick = onFeedingPointSelect,
            onInitialLocationDisplay = onInitialLocationDisplay,
            onRouteResult = onRouteResult,
            onCameraChange = onCameraChange,
            onMapClick = onMapClick
        )

        when {
            state.feedingRouteState is FeedingRouteState.Active && state.timerState is TimerState.Active -> {
                RouteTopBar(
                    modifier = Modifier
                        .statusBarsPadding()
                        .padding(top = 16.dp)
                        .padding(horizontal = 20.dp),
                    timeLeft = context.formatNumberToHourMin(state.timerState.timeLeft)
                        ?: stringResource(R.string.calculating_route),
                    distanceLeft = state.feedingRouteState.distanceLeft?.run {
                        " • ${context.formatMetersToKilometers(this)}"
                    } ?: "",
                    onCancelClick = onCancelRouteClick
                )
            }

            else -> {
                AnimealSwitch(
                    modifier = Modifier
                        .statusBarsPadding()
                        .align(alignment = Alignment.TopCenter)
                        .padding(top = 24.dp),
                    onSelectTab = onSelectTab,
                    defaultAnimalType = state.feedingPointState.defaultAnimalType
                )
            }
        }

        HomeFABBox(
            modifier = Modifier
                .bottomBarPadding()
                .align(alignment = Alignment.BottomEnd),
            feedingsButtonState = state.feedingsButtonState,
            onGeoFABClick = { onGeolocationClick(mapboxMapView) },
            onFeedingsFABClick = onFeedingsClick
        )
    }
}

@Composable
private fun MapView.LogoAndAttributionMarginsEffect(
    maxHeight: Dp,
    bottomSheetState: AnimealBottomSheetState
) {
    with(LocalDensity.current) {
        val componentMargin = 4.dp.toPx()
        val marginBottom by remember {
            derivedStateOf {
                val currentBottomSheetHeight = maxHeight.toPx() - bottomSheetState.offset.value

                max(currentBottomSheetHeight, bottomBarHeight.toPx()) + componentMargin
            }
        }

        LaunchedEffect(Unit) {
            logo.marginLeft += componentMargin
            attribution.marginLeft += componentMargin
        }

        DisposableEffect(marginBottom) {
            logo.marginBottom = marginBottom
            attribution.marginBottom = marginBottom

            onDispose { }
        }
    }
}

@Composable
private fun ShowUserCurrentLocation(
    state: HomeState,
    mapboxMapView: MapView
) {
    LaunchedEffect(
        key1 = state.permissionsState.geolocationPermissionStatus,
        key2 = state.gpsSettingState
    ) {
        if (state.permissionsState.geolocationPermissionStatus == PermissionStatus.Granted &&
            state.gpsSettingState == GpsSettingState.Enabled
        ) {
            mapboxMapView.showCurrentLocation(state.locationState.location)
        }
    }
}

@Composable
private fun MapboxMap(
    mapboxMapView: MapView,
    state: HomeState,
    onFeedingPointClick: (point: FeedingPointModel) -> Unit,
    onInitialLocationDisplay: () -> Unit,
    onRouteResult: (result: RouteResult) -> Unit,
    onCameraChange: () -> Unit,
    onMapClick: (Point) -> Unit
) {
    val markerController = remember(mapboxMapView) {
        MarkerController(
            mapView = mapboxMapView,
            onFeedingPointClick = onFeedingPointClick
        )
    }

    // If we return from other tab and there was a route active in map the camera zoom will not work
    // so we have to make sure the map is loaded before setting location
    val styleLoadedCallback = StyleLoadedCallback {
        when (state.feedingRouteState) {
            is FeedingRouteState.Disabled -> mapboxMapView.setLocation(state.locationState.location)
            is FeedingRouteState.Active -> setLocationOnRoute(mapboxMapView, state)
        }
    }

    LaunchedEffect(key1 = state.feedingPointState.feedingPoints) {
        markerController.drawMarkers(
            feedingPoints = state.feedingPointState.feedingPoints
        )
    }

    LaunchedEffect(key1 = state.feedingPointState.currentFeedingPoint) {
        if (state.feedingRouteState is FeedingRouteState.Active) {
            markerController.drawSelectedMarkerBackground(null)
        } else {
            markerController.drawSelectedMarkerBackground(state.feedingPointState.currentFeedingPoint)
        }
    }

    LaunchedEffect(key1 = state.locationState) {
        when (state.locationState) {
            is LocationState.UndefinedLocation -> {
                mapboxMapView.setLocation(state.locationState.location)
            }

            is LocationState.InitialLocation -> {
                mapboxMapView.setLocation(state.locationState.location)
                onInitialLocationDisplay()
            }

            else -> {}
        }
    }

    mapboxMapView.mapboxMap.subscribeStyleLoaded(styleLoadedCallback)
    mapboxMapView.GesturesListeners(onMapClick, onCameraChange)

    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { mapboxMapView }
    )

    RouteView(mapView = mapboxMapView, state = state, onRouteResult = onRouteResult)
}

@Composable
private fun rememberMapboxMapView(homeState: HomeState): MapView {
    return rememberMapViewWithLifecycle(
        mapBoxInitOptions = rememberMapInitOptions(
            MapBoxInitOptions(
                publicKey = homeState.mapBoxPublicKey,
                styleUrl = homeState.mapBoxStyleUri
            )
        ),
        uiSettings = rememberMapUiSettings(
            MapUiSettings(
                scalebar = false,
                userLocationOnMap = true,
                compassEnabled = false
            )
        )
    )
}

internal fun MapView.showCurrentLocation(location: MapLocation) {
    mapboxMap.setCamera(
        CameraOptions.Builder()
            .center(Point.fromLngLat(location.longitude, location.latitude))
            .build()
    )
}
