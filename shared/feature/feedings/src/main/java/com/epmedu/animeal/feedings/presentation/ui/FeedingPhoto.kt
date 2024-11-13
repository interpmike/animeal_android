package com.epmedu.animeal.feedings.presentation.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import coil.compose.AsyncImage
import coil.compose.AsyncImagePainter.State.Loading
import coil.request.ImageRequest
import com.epmedu.animeal.foundation.loading.ShimmerLoading
import com.epmedu.animeal.networkstorage.domain.NetworkFile

@Composable
internal fun FeedingPhoto(
    photo: NetworkFile,
    modifier: Modifier = Modifier
) {
    var isPhotoLoading by rememberSaveable(photo.url) { mutableStateOf(false) }

    Box(modifier = modifier) {
        AsyncImage(
            model = ImageRequest.Builder(LocalContext.current)
                .data(photo.url)
                .diskCacheKey(photo.name)
                .crossfade(true)
                .build(),
            contentDescription = null,
            modifier = Modifier.fillMaxSize(),
            contentScale = ContentScale.Fit,
            onState = { state ->
                isPhotoLoading = state is Loading
            }
        )
        if (isPhotoLoading) {
            ShimmerLoading(
                modifier = Modifier.fillMaxSize(),
                shape = RoundedCornerShape(8.dp)
            )
        }
    }
}