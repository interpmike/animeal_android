package com.epmedu.animeal.auth

import com.amplifyframework.auth.AuthUserAttribute
import com.amplifyframework.auth.AuthUserAttributeKey
import com.amplifyframework.auth.cognito.AWSCognitoAuthSession
import com.amplifyframework.auth.cognito.options.AWSCognitoAuthSignInOptions
import com.amplifyframework.auth.cognito.options.AuthFlowType
import com.amplifyframework.auth.exceptions.SessionExpiredException
import com.amplifyframework.auth.options.AuthFetchSessionOptions
import com.amplifyframework.auth.options.AuthSignUpOptions
import com.amplifyframework.auth.result.AuthSessionResult
import com.amplifyframework.kotlin.core.Amplify
import com.epmedu.animeal.auth.constants.UserAttributesKey
import com.epmedu.animeal.auth.error.WrongCodeError
import com.epmedu.animeal.common.data.wrapper.ApiResult
import com.epmedu.animeal.token.errorhandler.TokenExpirationHandler

internal class AuthAPIImpl(
    private val userAttributesAPI: UserAttributesAPI,
    private val errorHandler: TokenExpirationHandler
) : AuthAPI,
    TokenExpirationHandler by errorHandler {
    override var authenticationType: AuthenticationType = AuthenticationType.Mobile

    private val AWSCognitoAuthSession.isExpired
        get() = isSignedIn.not() &&
            (
                awsCredentialsResult.error is SessionExpiredException ||
                    identityIdResult.error is SessionExpiredException ||
                    userPoolTokensResult.error is SessionExpiredException ||
                    userSubResult.error is SessionExpiredException
                )

    private val AWSCognitoAuthSession.isSignedInWithoutErrors
        get() = isSignedIn &&
            awsCredentialsResult.type == AuthSessionResult.Type.SUCCESS &&
            identityIdResult.type == AuthSessionResult.Type.SUCCESS &&
            userPoolTokensResult.type == AuthSessionResult.Type.SUCCESS &&
            userSubResult.type == AuthSessionResult.Type.SUCCESS

    override suspend fun getCurrentUserId() = Amplify.Auth.getCurrentUser().userId

    /** Keep in mind: verification of session expiration (session.isExpired) works only for Mobile authorization flow.
     * Wherever this method is used for Facebook flow, verify that next steps will be ready to handle
     * NotAuthorizedException due to possible refresh token expiration */
    override suspend fun isSignedIn(): Boolean {
        val options = AuthFetchSessionOptions.builder()
            .build()
        return when (val session = Amplify.Auth.fetchAuthSession(options)) {
            is AWSCognitoAuthSession -> {
                if (session.isExpired) {
                    signOut()
                    false
                } else {
                    session.isSignedInWithoutErrors
                }
            }

            else -> {
                session.isSignedIn
            }
        }
    }

    override suspend fun signUp(
        phone: String,
        password: String,
    ): ApiResult<Unit> {
        val attrs = mapOf(
            AuthUserAttributeKey.phoneNumber() to phone,
        )

        val options = AuthSignUpOptions.builder()
            .userAttributes(attrs.map { AuthUserAttribute(it.key, it.value) })
            .build()

        return try {
            val result = Amplify.Auth.signUp(
                phone,
                password,
                options,
            )

            if (result.isSignUpComplete) {
                ApiResult.Success(Unit)
            } else {
                ApiResult.Failure(Exception())
            }
        } catch (e: Exception) {
            if (isRefreshTokenHasExpiredException(e)) {
                handleRefreshTokenExpiration()
            }
            ApiResult.Failure(e)
        }
    }

    override suspend fun signIn(phoneNumber: String): ApiResult<Unit> {
        val authSignInOptions = AWSCognitoAuthSignInOptions.builder()
            .authFlowType(AuthFlowType.CUSTOM_AUTH_WITHOUT_SRP)
            .build()

        return try {
            Amplify.Auth.signIn(
                phoneNumber,
                "",
                authSignInOptions,
            )

            ApiResult.Success(Unit)
        } catch (e: Exception) {
            handleException(e)
            return ApiResult.Failure(e)
        }
    }

    override suspend fun confirmSignIn(code: String): ApiResult<Unit> {
        return try {
            val confirmSignIn = Amplify.Auth.confirmSignIn(code)

            if (confirmSignIn.isSignedIn) {
                ApiResult.Success(Unit)
            } else {
                ApiResult.Failure(WrongCodeError())
            }
        } catch (e: Exception) {
            handleException(e)
            return ApiResult.Failure(e)
        }
    }

    override suspend fun confirmResendCode(
        code: String,
    ): ApiResult<Unit> {
        return try {
            Amplify.Auth.confirmUserAttribute(
                AuthUserAttributeKey.phoneNumber(),
                code,
            )
            ApiResult.Success(Unit)
        } catch (e: Exception) {
            handleException(e)
            ApiResult.Failure(e)
        }
    }

    override suspend fun sendCode(
        phoneNumber: String,
    ): ApiResult<Unit> {
        return when (authenticationType) {
            AuthenticationType.Mobile -> signIn(phoneNumber)
            is AuthenticationType.Facebook -> sendPhoneCodeByUpdatingAttribute(phoneNumber)
        }
    }

    override suspend fun signOut(): ApiResult<Unit> {
        return try {
            Amplify.Auth.signOut()
            ApiResult.Success(Unit)
        } catch (e: Exception) {
            ApiResult.Failure(e)
        }
    }

    private fun handleException(e: Exception) {
        if (isRefreshTokenHasExpiredException(e)) {
            handleRefreshTokenExpiration()
        }
    }

    private suspend fun sendPhoneCodeByUpdatingAttribute(phoneNumber: String): ApiResult<Unit> {
        return userAttributesAPI.updateUserAttributes(
            userAttributes = listOf(
                AuthUserAttribute(UserAttributesKey.phoneNumberKey, phoneNumber)
            )
        )
    }
}