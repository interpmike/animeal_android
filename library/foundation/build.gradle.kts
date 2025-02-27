plugins {
    id("AnimealPlugin")
    id("com.android.library")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.epmedu.animeal.foundation"
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))

    implementation(projects.library.extensions)
    implementation(projects.library.resources)

    implementation(libs.accompanist.systemuicontroller)

    implementation(libs.androidx.lifecycle)

    implementation(libs.compose.material)
    implementation(libs.compose.material.icons.extended)
    implementation(libs.compose.richtext)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.preview)

    implementation(libs.htmlText)

    debugImplementation(libs.compose.ui.tooling)
}
