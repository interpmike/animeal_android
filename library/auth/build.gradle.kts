plugins {
    id("AnimealPlugin")
    id("com.android.library")
    id("com.google.devtools.ksp")
    id("dagger.hilt.android.plugin")
}

android {
    namespace = "com.epmedu.animeal.auth"
}

animealPlugin {
    compose = false
}

dependencies {
    implementation(projects.library.common)
    implementation(projects.library.extensions)
    implementation(projects.library.token)

    implementation(platform(libs.androidx.compose.bom))

    implementation(libs.androidx.appcompat)
    implementation(libs.compose.runtime)

    implementation(libs.amplify.core)
    implementation(libs.amplify.aws.auth.cognito)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
}
