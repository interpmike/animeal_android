package com.epmedu.animeal.tabs.search.presentation.search

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.epmedu.animeal.common.presentation.viewmodel.delegate.ActionDelegate
import com.epmedu.animeal.common.presentation.viewmodel.delegate.DefaultStateDelegate
import com.epmedu.animeal.common.presentation.viewmodel.delegate.StateDelegate
import com.epmedu.animeal.feeding.domain.model.FeedingPoint
import com.epmedu.animeal.feeding.domain.usecase.AddFeedingPointToFavouritesUseCase
import com.epmedu.animeal.feeding.domain.usecase.RemoveFeedingPointFromFavouritesUseCase
import com.epmedu.animeal.foundation.tabs.model.AnimalType
import com.epmedu.animeal.tabs.search.domain.SearchCatsFeedingPointsUseCase
import com.epmedu.animeal.tabs.search.domain.SearchDogsFeedingPointsUseCase
import com.epmedu.animeal.tabs.search.presentation.search.SearchScreenEvent.DismissWillFeedDialog
import com.epmedu.animeal.tabs.search.presentation.search.SearchScreenEvent.FavouriteChange
import com.epmedu.animeal.tabs.search.presentation.search.SearchScreenEvent.FeedingPointHidden
import com.epmedu.animeal.tabs.search.presentation.search.SearchScreenEvent.FeedingPointSelected
import com.epmedu.animeal.tabs.search.presentation.search.SearchScreenEvent.Search
import com.epmedu.animeal.tabs.search.presentation.search.SearchScreenEvent.ShowWillFeedDialog
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.collections.immutable.toImmutableList
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

@HiltViewModel
class SearchScreenViewModel @Inject constructor(
    actionDelegate: ActionDelegate,
    private val searchCatsFeedingPointsUseCase: SearchCatsFeedingPointsUseCase,
    private val searchDogsFeedingPointsUseCase: SearchDogsFeedingPointsUseCase,
    private val addFeedingPointToFavouritesUseCase: AddFeedingPointToFavouritesUseCase,
    private val removeFeedingPointFromFavouritesUseCase: RemoveFeedingPointFromFavouritesUseCase
) : ViewModel(),
    StateDelegate<SearchState> by DefaultStateDelegate(initialState = SearchState()),
    ActionDelegate by actionDelegate {

    init {
        viewModelScope.launch {
            stateFlow.collectLatest { state ->
                combine(
                    searchDogsFeedingPointsUseCase(state.dogsQuery),
                    searchCatsFeedingPointsUseCase(state.catsQuery)
                ) { dogs, cats ->
                    updateState {
                        copy(
                            catsFeedingPoints = cats.toImmutableList(),
                            dogsFeedingPoints = dogs.toImmutableList(),
                            favourites = (cats + dogs).filter { it.isFavourite }.toImmutableList()
                        )
                    }
                }.collect()
            }
        }
    }

    fun handleEvents(event: SearchScreenEvent) {
        when (event) {
            is FavouriteChange -> handleFavouriteChange(event)
            is FeedingPointSelected -> updateState { copy(showingFeedingPoint = event.feedingPoint) }
            is FeedingPointHidden -> updateState { copy(showingFeedingPoint = null) }
            is ShowWillFeedDialog -> updateState { copy(showingWillFeedDialog = true) }
            is DismissWillFeedDialog -> updateState { copy(showingWillFeedDialog = false) }
            is Search -> handleSearch(event)
        }
    }

    private fun handleSearch(event: Search) {
        when (event.animalType) {
            AnimalType.Dogs -> updateState { copy(dogsQuery = event.query) }
            AnimalType.Cats -> updateState { copy(catsQuery = event.query) }
        }
    }

    private fun handleFavouriteChange(event: FavouriteChange) {
        when {
            event.isFavourite -> addFeedingPointToFavourites(event.feedingPoint)
            else -> removeFeedingPointFromFavourites(event.feedingPoint)
        }
    }

    private fun addFeedingPointToFavourites(feedingPoint: FeedingPoint) {
        markFeedingPointAsFavourite(feedingPoint)
        tryAddingFeedingPointToFavourites(feedingPoint)
    }

    private fun removeFeedingPointFromFavourites(feedingPoint: FeedingPoint) {
        unmarkFeedingPointFromFavourites(feedingPoint)
        tryRemovingFeedingPointFromFavourites(feedingPoint)
    }

    private fun markFeedingPointAsFavourite(feedingPoint: FeedingPoint) {
        updateState {
            copy(
                favourites = (favourites + feedingPoint).toImmutableList(),
                showingFeedingPoint = when (showingFeedingPoint) {
                    feedingPoint -> feedingPoint.copy(isFavourite = true)
                    else -> showingFeedingPoint
                }
            )
        }
    }

    private fun unmarkFeedingPointFromFavourites(feedingPoint: FeedingPoint) {
        updateState {
            copy(
                favourites = (favourites - feedingPoint).toImmutableList(),
                showingFeedingPoint = when (showingFeedingPoint) {
                    feedingPoint -> feedingPoint.copy(isFavourite = false)
                    else -> showingFeedingPoint
                }
            )
        }
    }

    private fun tryAddingFeedingPointToFavourites(feedingPoint: FeedingPoint) {
        viewModelScope.launch {
            performAction(
                action = { addFeedingPointToFavouritesUseCase(feedingPoint.id) },
                onError = { unmarkFeedingPointFromFavourites(feedingPoint) }
            )
        }
    }

    private fun tryRemovingFeedingPointFromFavourites(feedingPoint: FeedingPoint) {
        viewModelScope.launch {
            performAction(
                action = { removeFeedingPointFromFavouritesUseCase(feedingPoint.id) },
                onError = { markFeedingPointAsFavourite(feedingPoint) }
            )
        }
    }
}
