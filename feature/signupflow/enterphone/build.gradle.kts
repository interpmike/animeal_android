plugins {
    id("AnimealPlugin")
    id("com.android.library")
    id("com.google.devtools.ksp")
    id("dagger.hilt.android.plugin")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.epmedu.animeal.signup.enterphone"
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))

    implementation(projects.library.auth)
    implementation(projects.library.common)
    implementation(projects.library.extensions)
    implementation(projects.library.foundation)
    implementation(projects.library.navigation)
    implementation(projects.library.resources)

    implementation(projects.shared.feature.profile)

    implementation(libs.amplify.aws.auth.cognito)
    implementation(libs.amplify.core)

    implementation(libs.androidx.datastore)
    implementation(libs.androidx.viewmodel)

    implementation(libs.compose.material)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.preview)
    implementation(libs.androidx.emoji2)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
}