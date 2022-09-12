package com.epmedu.animeal.home

import com.epmedu.animeal.common.data.model.MapLocation
import com.epmedu.animeal.model.FeedingPointUi
import com.mapbox.maps.Style

data class HomeState(
    val currentLocation: MapLocation = MapLocation(),
    val mapBoxPublicKey: String = "",
    val mapBoxStyleUri: String = Style.MAPBOX_STREETS,
    val areFeedingPointsLoading: Boolean = false,
    val feedingPoints: List<FeedingPointUi> = emptyList()
)