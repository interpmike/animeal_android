package com.epmedu.animeal.api.feeding

import com.amplifyframework.datastore.generated.model.Feeding
import com.amplifyframework.datastore.generated.model.FeedingPoint
import com.epmedu.animeal.common.data.wrapper.ApiResult
import kotlinx.coroutines.flow.Flow

interface FeedingPointApi {

    fun getAllFeedingPoints(): Flow<List<FeedingPoint>>

    fun subscribeToFeedingPointsUpdates(): Flow<FeedingPoint>

    fun subscribeToFeedingPointsCreation(): Flow<FeedingPoint>

    fun subscribeToFeedingPointsDeletion(): Flow<FeedingPoint>

    fun getUserFeedings(userId: String): Flow<List<Feeding>>

    suspend fun startFeeding(feedingPointId: String): ApiResult<String>

    suspend fun cancelFeeding(feedingPointId: String): ApiResult<String>

    suspend fun rejectFeeding(feedingPointId: String, reason: String): ApiResult<String>

    suspend fun finishFeeding(feedingPointId: String, images: List<String>): ApiResult<String>
}