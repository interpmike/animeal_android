package com.epmedu.animeal.home.presentation.viewmodel.handlers.route

import com.epmedu.animeal.common.constants.Arguments.FORCED_FEEDING_POINT_ID
import com.epmedu.animeal.common.presentation.viewmodel.delegate.StateDelegate
import com.epmedu.animeal.home.domain.usecases.ForcedArgumentsUseCase
import com.epmedu.animeal.home.presentation.HomeScreenEvent.RouteEvent
import com.epmedu.animeal.home.presentation.HomeScreenEvent.RouteEvent.FeedingRouteUpdateRequest
import com.epmedu.animeal.home.presentation.HomeScreenEvent.RouteEvent.FeedingTimerUpdateRequest
import com.epmedu.animeal.home.presentation.model.FeedingRouteState
import com.epmedu.animeal.home.presentation.viewmodel.HomeState

internal class DefaultRouteHandler(
    stateDelegate: StateDelegate<HomeState>,
    private val forcedArgumentsUseCase: ForcedArgumentsUseCase
) : RouteHandler,
    StateDelegate<HomeState> by stateDelegate {

    private var showFullRoad: Boolean = false

    override fun handleRouteEvent(event: RouteEvent) {
        when (event) {
            is FeedingRouteUpdateRequest -> updateRoute(event)
            is FeedingTimerUpdateRequest -> updateTimer(event)
        }
    }

    override fun startRoute() {
        if (forcedArgumentsUseCase<String>(FORCED_FEEDING_POINT_ID, hashCode()) == null) {
            showFullRoad = true
        }
        updateState { copy(feedingRouteState = FeedingRouteState.Active(showFullRoad = showFullRoad), isError = false) }
    }

    override fun stopRoute() {
        updateState { copy(feedingRouteState = FeedingRouteState.Disabled) }
    }

    private fun updateRoute(event: FeedingRouteUpdateRequest) {
        if (state.feedingRouteState is FeedingRouteState.Active) {
            updateState {
                copy(
                    feedingRouteState = FeedingRouteState.Active(
                        showFullRoad = showFullRoad,
                        event.result.distanceLeft,
                        state.feedingRouteState.timeLeft,
                        event.result.routeData
                    )
                )
            }
            showFullRoad = false
        }
    }

    private fun updateTimer(event: FeedingTimerUpdateRequest) {
        if (state.feedingRouteState is FeedingRouteState.Active) {
            updateState {
                copy(
                    feedingRouteState = FeedingRouteState.Active(
                        showFullRoad = showFullRoad,
                        state.feedingRouteState.distanceLeft,
                        event.timeLeft,
                        state.feedingRouteState.routeData
                    )
                )
            }
        }
    }
}