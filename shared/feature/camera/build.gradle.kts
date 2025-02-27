plugins {
    id("AnimealPlugin")
    id("com.android.library")
    id("com.google.devtools.ksp")
    id("dagger.hilt.android.plugin")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.epmedu.animeal.camera"
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))

    implementation(projects.library.common)
    implementation(projects.library.extensions)
    implementation(projects.library.foundation)
    implementation(projects.library.resources)

    implementation(projects.shared.feature.networkstorage)

    implementation(libs.androidx.datastore)
    implementation(libs.androidx.viewmodel)
    implementation(libs.amplify.aws.auth.cognito)

    implementation(libs.camera.core)
    implementation(libs.camera.camera2)
    implementation(libs.camera.view)
    implementation(libs.camera.lifecycle)

    implementation(libs.compose.material)
    implementation(libs.compose.material.icons.extended)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.preview)
    implementation(libs.androidx.activity.compose)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
}