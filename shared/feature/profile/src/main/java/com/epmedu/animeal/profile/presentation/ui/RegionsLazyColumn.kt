@file:OptIn(ExperimentalMaterialApi::class)

package com.epmedu.animeal.profile.presentation.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material.ListItem
import androidx.compose.material.MaterialTheme
import androidx.compose.material.ModalBottomSheetState
import androidx.compose.material.ModalBottomSheetValue
import androidx.compose.material.Text
import androidx.compose.material.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import com.epmedu.animeal.foundation.preview.AnimealPreview
import com.epmedu.animeal.foundation.theme.AnimealTheme
import com.epmedu.animeal.profile.domain.model.Region
import com.epmedu.animeal.profile.domain.model.codesListText
import com.epmedu.animeal.profile.domain.model.countryName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

@Composable
fun RegionsLazyColumn(
    scope: CoroutineScope,
    bottomSheetState: ModalBottomSheetState,
    onRegionClick: (Region) -> Unit
) {
    LazyColumn(
        modifier = Modifier.background(MaterialTheme.colors.background)
    ) {
        items(
            items = Region.entries.toTypedArray().apply {
                sortBy { region -> region.countryName() }
            }
        ) { region ->
            ListItem(
                modifier = Modifier.clickable {
                    scope.launch { bottomSheetState.hide() }
                    onRegionClick(region)
                },
                text = {
                    Text(
                        region.codesListText()
                    )
                },
            )
        }
    }
}

@AnimealPreview
@Composable
fun RegionsLazyColumnPreview() {
    AnimealTheme {
        RegionsLazyColumn(
            scope = rememberCoroutineScope(),
            bottomSheetState = rememberModalBottomSheetState(initialValue = ModalBottomSheetValue.Hidden),
            onRegionClick = {}
        )
    }
}