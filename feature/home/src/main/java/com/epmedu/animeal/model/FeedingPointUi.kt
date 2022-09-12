package com.epmedu.animeal.model

import com.epmedu.animeal.common.data.enum.AnimalPriority
import com.epmedu.animeal.common.data.enum.AnimalState
import com.epmedu.animeal.common.data.enum.Remoteness
import com.epmedu.animeal.common.data.model.FeedingPoint
import com.epmedu.animeal.foundation.switch.Tab
import com.epmedu.animeal.resources.R
import com.mapbox.geojson.Point

data class FeedingPointUi(
    val id: Int, // For future implementations
    val priority: AnimalPriority,
    val status: AnimalState,
    val tab: Tab,
    val isFavourite: Boolean = false,
    val remoteness: Remoteness = Remoteness.ANY,
    var coordinates: Point
) {

    companion object {
        fun FeedingPoint.toUi(): FeedingPointUi {
            return FeedingPointUi(
                id,
                priority,
                status,
                tab,
                isFavourite,
                remoteness,
                Point.fromLngLat(xCoordinate, yCoordinate)
            )
        }
    }

    fun getDrawableRes(): Int =
        when {
            isFavourite -> {
                when (status) {
                    AnimalState.RED -> R.drawable.ic_favstate_favouritehungry_high
                    AnimalState.YELLOW -> R.drawable.ic_favstate_favouritehungry_medium
                    AnimalState.GREEN -> R.drawable.ic_favstate_favouritehungry_low
                }
            }
            tab == Tab.Dogs -> {
                when (status) {
                    AnimalState.RED -> R.drawable.ic_dogsstate_doghungry_high
                    AnimalState.YELLOW -> R.drawable.ic_dogsstate_doghungry_medium
                    AnimalState.GREEN -> R.drawable.ic_dogsstate_doghungry_low
                }
            }
            else -> {
                when (status) {
                    AnimalState.RED -> R.drawable.ic_catsstate_cathungry_high
                    AnimalState.YELLOW -> R.drawable.ic_catsstate_cathungry_medium
                    AnimalState.GREEN -> R.drawable.ic_catsstate_cathungry_low
                }
            }
        }
}
