package com.epmedu.animeal.common.component

import kotlinx.coroutines.flow.Flow

interface AppSettingsProvider {

    fun getAppSettings(): Flow<AppSettings>

    suspend fun updateAppSettings(action: AppSettingsUpdateScope.() -> Unit)
}

interface AppSettingsUpdateScope {
    var isGeolocationPermissionRationaleShown: Boolean
    var animalType: String
}

data class AppSettings(
    val isGeolocationPermissionRationaleShown: Boolean,
    val animalType: String
)