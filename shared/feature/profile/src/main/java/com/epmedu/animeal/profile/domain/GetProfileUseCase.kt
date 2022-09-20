package com.epmedu.animeal.profile.domain

import com.epmedu.animeal.profile.data.repository.ProfileRepository

class GetProfileUseCase(private val repository: ProfileRepository) {
    suspend operator fun invoke() = repository.getProfile()
}