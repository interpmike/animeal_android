plugins {
    id("AnimealPlugin")
    id("com.android.library")
    id("com.google.devtools.ksp")
    id("dagger.hilt.android.plugin")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.epmedu.animeal.tabs"
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))

    implementation(projects.feature.tabsflow.analytics)
    implementation(projects.feature.tabsflow.favourites)
    implementation(projects.feature.tabsflow.home)
    implementation(projects.feature.tabsflow.moreflow.host)
    implementation(projects.feature.tabsflow.search)

    implementation(projects.shared.feature.feedings)
    implementation(projects.shared.feature.timer)

    implementation(projects.library.foundation)
    implementation(projects.library.navigation)
    implementation(projects.library.resources)
    implementation(projects.library.common)

    implementation(libs.compose.material)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.preview)

    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
}
