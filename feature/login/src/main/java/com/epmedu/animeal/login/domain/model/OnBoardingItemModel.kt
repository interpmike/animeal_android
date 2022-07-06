package com.epmedu.animeal.login.domain.model

import androidx.annotation.DrawableRes

data class OnBoardingItemModel(
    @DrawableRes val imageId: Int,
    val title: String,
    val text: String,
)
