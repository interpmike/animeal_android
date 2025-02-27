package com.epmedu.animeal.api.feeding

import ApproveFeedingMutation
import CancelFeedingMutation
import ExpireFeedingMutation
import FinishFeedingMutation
import RejectFeedingMutation
import StartFeedingMutation
import com.epmedu.animeal.api.AnimealApi
import com.epmedu.animeal.common.data.wrapper.ApiResult

internal class FeedingActionApiImpl(
    private val animealApi: AnimealApi
) : FeedingActionApi {

    override suspend fun startFeeding(feedingPointId: String): ApiResult<String> {
        return animealApi.launchMutation(
            mutation = StartFeedingMutation(feedingPointId),
            responseClass = String::class.java
        )
    }

    override suspend fun cancelFeeding(feedingPointId: String): ApiResult<String> {
        return animealApi.launchMutation(
            mutation = CancelFeedingMutation(feedingPointId, CANCEL_FEEDING_REASON),
            responseClass = String::class.java
        )
    }

    override suspend fun expireFeeding(feedingPointId: String): ApiResult<String> {
        return animealApi.launchMutation(
            mutation = ExpireFeedingMutation(feedingPointId, EXPIRE_FEEDING_REASON),
            responseClass = String::class.java
        )
    }

    override suspend fun finishFeeding(
        feedingPointId: String,
        images: List<String>
    ): ApiResult<String> {
        return animealApi.launchMutation(
            mutation = FinishFeedingMutation(feedingPointId, images),
            responseClass = String::class.java
        )
    }

    override suspend fun approveFeeding(feedingPointId: String): ApiResult<String> {
        return animealApi.launchMutation(
            mutation = ApproveFeedingMutation(feedingPointId, APPROVE_FEEDING_REASON, null),
            responseClass = String::class.java
        )
    }

    override suspend fun rejectFeeding(feedingPointId: String, reason: String): ApiResult<String> {
        return animealApi.launchMutation(
            mutation = RejectFeedingMutation(feedingPointId, reason, null),
            responseClass = String::class.java
        )
    }

    private companion object {
        const val CANCEL_FEEDING_REASON = "Canceled by user"
        const val EXPIRE_FEEDING_REASON = "Feeding time has expired"
        const val APPROVE_FEEDING_REASON = "The request includes all necessary details."
    }
}