package com.epmedu.animeal.feedings.presentation.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.epmedu.animeal.feedings.presentation.model.FeedingModel
import com.epmedu.animeal.resources.R

@Composable
internal fun FeedingItemDetails(feedingModel: FeedingModel) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(vertical = 2.dp),
        verticalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = feedingModel.title,
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 16.dp),
                style = MaterialTheme.typography.subtitle1,
                fontWeight = FontWeight.Bold,
                overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colors.onSurface,
                maxLines = 1,
            )
            Text(
                text = feedingModel.elapsedTime,
                style = MaterialTheme.typography.body2,
                overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colors.onBackground,
                maxLines = 1,
            )
        }

        Text(
            text = stringResource(
                id = R.string.fed_by,
                feedingModel.feeder.ifEmpty { stringResource(R.string.unknown_user) }
            ),
            style = MaterialTheme.typography.subtitle2,
            overflow = TextOverflow.Ellipsis,
            color = MaterialTheme.colors.onSurface,
            maxLines = 2,
        )
        FeedingStatusUi(status = feedingModel.status)
    }
}