package com.epmedu.animeal.feedings.di

import com.epmedu.animeal.feedings.domain.usecase.GetIsNewFeedingPendingUseCase
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ViewModelComponent
import dagger.hilt.android.scopes.ViewModelScoped

@Module
@InstallIn(ViewModelComponent::class)
object FeedingsDomainModule {

    @ViewModelScoped
    @Provides
    fun providesGetIsNewFeedingPendingUseCase() = GetIsNewFeedingPendingUseCase()
}