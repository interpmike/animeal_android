package com.epmedu.animeal.feedings.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Card
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.MaterialTheme
import androidx.compose.material.TabRow
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.epmedu.animeal.feedings.presentation.model.FeedingModel
import com.epmedu.animeal.feedings.presentation.model.FeedingModelStatus
import com.epmedu.animeal.feedings.presentation.ui.FeedingItem
import com.epmedu.animeal.feedings.presentation.viewmodel.FeedingFilterCategory
import com.epmedu.animeal.feedings.presentation.viewmodel.FeedingsState
import com.epmedu.animeal.foundation.preview.AnimealPreview
import com.epmedu.animeal.foundation.tabs.AnimealSwitchTab
import com.epmedu.animeal.foundation.tabs.TabIndicator
import com.epmedu.animeal.foundation.theme.AnimealTheme
import com.epmedu.animeal.foundation.topbar.BackButton
import com.epmedu.animeal.foundation.topbar.TopBar
import com.epmedu.animeal.resources.R
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList

@Composable
internal fun FeedingsScreenUI(
    state: FeedingsState,
    onBack: () -> Unit,
    onFilterClick: (FeedingFilterCategory) -> Unit
) {
    Column(modifier = Modifier.fillMaxSize()) {
        TopBar(
            title = stringResource(id = R.string.feedings),
            navigationIcon = {
                BackButton(onClick = onBack)
            }
        )
        when {
            state.isLoading -> {
                LoadingState()
            }

            state.feedings.isEmpty() -> {
                EmptyState()
            }

            else -> {
                FeedingsCategoryTab(state.feedingsFiltered, state.feedingsCategory, onFilterClick)
            }
        }
    }
}

@Composable
fun FeedingsCategoryTab(
    feedings: ImmutableList<FeedingModel>,
    feedingsCategory: FeedingFilterCategory,
    onFilterClick: (FeedingFilterCategory) -> Unit
) {
    var selectedTab by remember { mutableStateOf(feedingsCategory) }

    Column(modifier = Modifier
        .padding(start = 30.dp, end = 30.dp, top = 20.dp)
    ) {
        Card(elevation = 5.dp, shape = RoundedCornerShape(9.dp)) {
            TabRow(
                selectedTabIndex = selectedTab.ordinal,
                backgroundColor = MaterialTheme.colors.background,
                modifier = Modifier
                    .height(36.dp),
                indicator = { tabPositions ->
                    TabIndicator(tabPositions, feedingsCategory)
                },
                divider = {}
            ) {
                FeedingFilterCategory.values().forEach { type ->
                    AnimealSwitchTab(
                        titleResId = type.title,
                        selected = selectedTab == type,
                        onClick = {
                            selectedTab = type
                            onFilterClick(type)
                        })
                }
            }
        }
        if (feedings.isEmpty()) {
            EmptyState()
        } else {
            FeedingList(feedings)
        }
    }
}

@Composable
private fun LoadingState() {
    Box(modifier = Modifier.fillMaxSize()) {
        CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
    }
}

@Composable
private fun EmptyState() {
    Box(
        modifier = Modifier.fillMaxSize()
    ) {
        Text(
            text = stringResource(R.string.no_feedings),
            modifier = Modifier.align(Alignment.Center),
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun FeedingList(feedings: List<FeedingModel>) {
    LazyColumn(
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 30.dp)
    ) {
        items(feedings) { feedingModel ->
            FeedingItem(feedingModel = feedingModel)
        }
    }
}

@AnimealPreview
@Composable
private fun FeedingScreenPreview() {
    val title = "FeedingPoint"
    val feedings = List(10) {
        FeedingModel(
            id = "0",
            title = title,
            feeder = "Feeder",
            status = FeedingModelStatus.values().random(),
            elapsedTime = "12 hours ago"
        )
    }
    AnimealTheme {
        FeedingsScreenUI(
            state = FeedingsState(
                feedings = feedings.toImmutableList(),
                feedingsFiltered = feedings.toImmutableList(),
            ),
            onBack = {},
            onFilterClick = {}
        )
    }
}

@AnimealPreview
@Composable
private fun FeedingScreenEmptyPreview() {
    AnimealTheme {
        FeedingsScreenUI(
            state = FeedingsState(),
            onBack = {},
            onFilterClick = {}
        )
    }
}

@AnimealPreview
@Composable
private fun FeedingScreenLoadingPreview() {
    AnimealTheme {
        FeedingsScreenUI(
            state = FeedingsState(isLoading = true),
            onBack = {},
            onFilterClick = {}
        )
    }
}