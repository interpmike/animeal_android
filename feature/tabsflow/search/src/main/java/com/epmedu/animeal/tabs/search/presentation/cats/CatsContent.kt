package com.epmedu.animeal.tabs.search.presentation.cats

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.epmedu.animeal.foundation.listitem.ExpandableListItem
import com.epmedu.animeal.tabs.search.presentation.AnimalExpandableList

@Composable
fun CatsContent() {
    ExpandableListItem(
        modifier = Modifier.padding(top = 16.dp),
        title = "City",
        onClick = {},
        isExpanded = true
    ) {
        AnimalExpandableList(
            padding = PaddingValues(0.dp),
            groupedPoints = emptyList()
        )
    }
}