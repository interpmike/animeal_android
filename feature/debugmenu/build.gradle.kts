plugins {
    id("AnimealPlugin")
    id("com.android.library")
    id("com.google.devtools.ksp")
    id("dagger.hilt.android.plugin")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.epmedu.animeal.debugmenu"
}

dependencies {
    debugImplementation(platform(libs.androidx.compose.bom))

    debugImplementation(projects.library.common)
    debugImplementation(projects.library.extensions)
    debugImplementation(projects.library.foundation)
    debugImplementation(projects.library.navigation)

    debugImplementation(projects.shared.feature.debugmenu)
    debugImplementation(projects.shared.feature.permissions)
    debugImplementation(projects.shared.feature.router)

    debugImplementation(libs.compose.ui)
    debugImplementation(libs.compose.ui.preview)
    debugImplementation(libs.compose.material)
    debugImplementation(libs.compose.material.icons.extended)
    debugImplementation(libs.androidx.viewmodel)
    debugImplementation(libs.androidx.viewmodel.compose)

    debugImplementation(libs.compose.ui.tooling)

    debugImplementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
}
