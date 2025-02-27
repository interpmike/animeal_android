package com.epmedu.animeal.api.feeding

import com.epmedu.animeal.common.data.wrapper.ApiResult

interface FeedingActionApi {

    suspend fun startFeeding(feedingPointId: String): ApiResult<String>

    suspend fun cancelFeeding(feedingPointId: String): ApiResult<String>

    suspend fun expireFeeding(feedingPointId: String): ApiResult<String>

    suspend fun finishFeeding(feedingPointId: String, images: List<String>): ApiResult<String>

    suspend fun approveFeeding(feedingPointId: String): ApiResult<String>

    suspend fun rejectFeeding(feedingPointId: String, reason: String): ApiResult<String>
}