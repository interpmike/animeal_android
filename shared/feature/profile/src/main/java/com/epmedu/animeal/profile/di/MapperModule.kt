package com.epmedu.animeal.profile.di

import com.epmedu.animeal.profile.data.mapper.AuthUserAttributesToIsPhoneVerifiedMapper
import com.epmedu.animeal.profile.data.mapper.AuthUserAttributesToProfileMapper
import com.epmedu.animeal.profile.data.mapper.ProfileToAuthUserAttributesMapper
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.components.ViewModelComponent
import dagger.hilt.android.scopes.ViewModelScoped

@Module
@InstallIn(ViewModelComponent::class)
object MapperModule {

    @ViewModelScoped
    @Provides
    fun provideAuthUserAttributesToProfileMapper() = AuthUserAttributesToProfileMapper()

    @ViewModelScoped
    @Provides
    fun provideAuthUserAttributesToIsPhoneVerifiedMapper() = AuthUserAttributesToIsPhoneVerifiedMapper()

    @ViewModelScoped
    @Provides
    fun provideProfileToAuthUserMapper() = ProfileToAuthUserAttributesMapper()
}