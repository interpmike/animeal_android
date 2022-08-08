package com.epmedu.animeal.component

import com.epmedu.animeal.BuildConfig
import com.epmedu.animeal.common.component.BuildConfigProvider

internal class BuildConfigProviderImpl : BuildConfigProvider {

    override val appVersion: String = BuildConfig.VERSION_NAME
    override val mapBoxPublicKey: String = BuildConfig.MAPBOX_PUBLIC_TOKEN
    override val mapBoxStyleURI: String = BuildConfig.MAPBOX_STYLE_URI
}