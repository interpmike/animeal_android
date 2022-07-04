package com.epmedu.animeal.feature.login.code.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.Divider
import androidx.compose.material.OutlinedTextField
import androidx.compose.material.Surface
import androidx.compose.material.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.text.isDigitsOnly
import com.epmedu.animeal.base.theme.AnimealTheme
import com.epmedu.animeal.base.theme.CursorColor

@Composable
internal fun DigitField(
    digit: Int?,
    onDigitInput: (Int?) -> Unit,
    onDigitRemove: () -> Unit,
    modifier: Modifier = Modifier,
    isError: Boolean = false
) {
    OutlinedTextField(
        value = digit?.toString() ?: "",
        onValueChange = { value ->
            when {
                value.isOneDigit() -> onDigitInput(value.toInt())
                value.isEmpty() -> onDigitRemove()
            }
        },
        modifier = modifier.size(width = 66.dp, height = 72.dp),
        textStyle = TextStyle(fontSize = 26.sp, textAlign = TextAlign.Center),
        isError = isError,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        singleLine = true,
        colors = TextFieldDefaults.outlinedTextFieldColors(
            cursorColor = CursorColor,
            focusedBorderColor = Color.Gray
        )
    )
}

private fun String.isOneDigit() = isDigitsOnly() && length == 1

@Preview
@Composable
private fun DigitFieldPreview() {
    AnimealTheme {
        Surface {
            Column {
                DigitField(
                    digit = null,
                    onDigitInput = {},
                    onDigitRemove = {},
                    modifier = Modifier.padding(8.dp)
                )
                Divider(modifier = Modifier.width(82.dp))
                DigitField(
                    digit = 4,
                    onDigitInput = {},
                    onDigitRemove = {},
                    modifier = Modifier.padding(8.dp),
                    isError = true
                )
            }
        }
    }
}