package com.epmedu.animeal.feeding.di

import com.epmedu.animeal.feeding.domain.repository.FavouriteRepository
import com.epmedu.animeal.feeding.domain.repository.FeedingPointRepository
import com.epmedu.animeal.feeding.domain.repository.FeedingRepository
import com.epmedu.animeal.feeding.domain.usecase.AddFeedingPointToFavouritesUseCase
import com.epmedu.animeal.feeding.domain.usecase.ExpireFeedingUseCase
import com.epmedu.animeal.feeding.domain.usecase.GetAllFeedingPointsUseCase
import com.epmedu.animeal.feeding.domain.usecase.GetAnimalTypeFromSettingsUseCase
import com.epmedu.animeal.feeding.domain.usecase.GetApprovedFeedingHistoriesUseCase
import com.epmedu.animeal.feeding.domain.usecase.GetFeedStateUseCase
import com.epmedu.animeal.feeding.domain.usecase.GetFeedingInProgressUseCase
import com.epmedu.animeal.feeding.domain.usecase.GetFeedingPointByIdUseCase
import com.epmedu.animeal.feeding.domain.usecase.GetFeedingPointByPriorityUseCase
import com.epmedu.animeal.feeding.domain.usecase.RemoveFeedingPointFromFavouritesUseCase
import com.epmedu.animeal.feeding.domain.usecase.UpdateFeedStateUseCase
import com.epmedu.animeal.permissions.domain.GetAppSettingsUseCase
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ViewModelComponent
import dagger.hilt.android.scopes.ViewModelScoped

@Module
@InstallIn(ViewModelComponent::class)
object FeedingDomainModule {

    @ViewModelScoped
    @Provides
    fun providesGetFeedingPointsByPriority(feedingPointRepository: FeedingPointRepository) =
        GetFeedingPointByPriorityUseCase(feedingPointRepository)

    @ViewModelScoped
    @Provides
    fun providesGetAllFeedingPointsUseCase(
        feedingPointRepository: FeedingPointRepository
    ): GetAllFeedingPointsUseCase = GetAllFeedingPointsUseCase(feedingPointRepository)

    @ViewModelScoped
    @Provides
    fun providesGetFeedingPointByIdUseCase(
        feedingPointRepository: FeedingPointRepository
    ): GetFeedingPointByIdUseCase = GetFeedingPointByIdUseCase(feedingPointRepository)

    @ViewModelScoped
    @Provides
    fun providesGetApprovedFeedingHistoriesUseCase(
        feedingRepository: FeedingRepository
    ): GetApprovedFeedingHistoriesUseCase = GetApprovedFeedingHistoriesUseCase(feedingRepository)

    @ViewModelScoped
    @Provides
    fun providesGetFeedingInProgressUseCase(
        feedingRepository: FeedingRepository
    ): GetFeedingInProgressUseCase = GetFeedingInProgressUseCase(feedingRepository)

    @ViewModelScoped
    @Provides
    fun providesGetFeedStateUseCase(
        feedingRepository: FeedingRepository
    ): GetFeedStateUseCase = GetFeedStateUseCase(feedingRepository)

    @ViewModelScoped
    @Provides
    fun providesUpdateFeedStateUseCase(
        feedingRepository: FeedingRepository
    ): UpdateFeedStateUseCase = UpdateFeedStateUseCase(feedingRepository)

    @ViewModelScoped
    @Provides
    fun providesAddFavouriteFeedingPointUseCase(
        repo: FavouriteRepository
    ) = AddFeedingPointToFavouritesUseCase(repo)

    @ViewModelScoped
    @Provides
    fun providesDeleteFavouriteFeedingPointUseCase(
        repo: FavouriteRepository
    ) = RemoveFeedingPointFromFavouritesUseCase(repo)

    @ViewModelScoped
    @Provides
    fun providesGetAnimalTypeFromSettingsUseCase(
        getAppSettingsUseCase: GetAppSettingsUseCase
    ) = GetAnimalTypeFromSettingsUseCase(getAppSettingsUseCase)

    @ViewModelScoped
    @Provides
    fun providesExpireFeedingUseCase(
        feedingRepository: FeedingRepository
    ) = ExpireFeedingUseCase(feedingRepository)
}