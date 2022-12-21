plugins {
    id("AnimealPlugin")
    id("com.android.library")
}

android {
    namespace = "com.epmedu.animeal.tabs.more.donate"
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))

    implementation(projects.library.extensions)
    implementation(projects.library.foundation)
    implementation(projects.library.navigation)
    implementation(projects.library.resources)
    implementation(projects.library.common)

    implementation(libs.compose.ui)
    implementation(libs.compose.ui.preview)
    implementation(libs.compose.material)
    debugImplementation(libs.compose.ui.tooling)
}