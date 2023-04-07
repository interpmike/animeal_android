package com.epmedu.animeal.auth

@Suppress("ComplexInterface")
interface AuthAPI {

    var authenticationType: AuthenticationType

    suspend fun getCurrentUserId(): String
    suspend fun isSignedIn(): Boolean
    fun setMobileAuthenticationType()
    fun setFacebookAuthenticationType(isPhoneNumberVerified: Boolean)
    fun signUp(
        phone: String,
        password: String,
        handler: AuthRequestHandler,
    )

    fun signIn(
        phoneNumber: String,
        handler: AuthRequestHandler,
    )
    fun confirmSignIn(
        code: String,
        handler: AuthRequestHandler
    )
    fun confirmResendCode(
        code: String,
        handler: AuthRequestHandler
    )
    fun sendCode(
        phoneNumber: String,
        handler: AuthRequestHandler,
    )
    fun signOut(
        handler: AuthRequestHandler
    )
}
