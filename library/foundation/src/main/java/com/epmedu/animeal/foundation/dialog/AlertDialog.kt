package com.epmedu.animeal.foundation.dialog

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.padding
import androidx.compose.material.ContentAlpha
import androidx.compose.material.LocalContentAlpha
import androidx.compose.material.MaterialTheme
import androidx.compose.material.ProvideTextStyle
import androidx.compose.material.Surface
import androidx.compose.material.Text
import androidx.compose.material.contentColorFor
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.layout.Measurable
import androidx.compose.ui.layout.layoutId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.epmedu.animeal.foundation.button.AnimealButton
import com.epmedu.animeal.foundation.preview.AnimealPreview
import com.epmedu.animeal.foundation.theme.AnimealTheme
import kotlin.math.max

private data class AlertDialogBaselineCalculator(
    val measurables: List<Measurable>,
    val constraints: Constraints,
    val offset: Int
) {
    val titlePlaceable = measurables.firstOrNull { it.layoutId == "title" }?.measure(
        constraints.copy(minHeight = 0)
    )
    val textPlaceable = measurables.firstOrNull { it.layoutId == "text" }?.measure(
        constraints.copy(minHeight = 0)
    )

    val buttonPlaceable = measurables.firstOrNull { it.layoutId == "buttons" }?.measure(
        constraints.copy(minHeight = 0)
    )

    private val titleHeightWithSpacing = titlePlaceable?.let {
        titlePlaceable.height + if (textPlaceable == null && buttonPlaceable == null) 0 else offset
    } ?: 0

    private val textHeightWithSpacing = textPlaceable?.let {
        textPlaceable.height + if (buttonPlaceable == null) 0 else offset
    } ?: 0

    private val buttonHeightWithSpacing = buttonPlaceable?.height ?: 0

    val titlePositionY = 0
    val textPositionY = titlePositionY + titleHeightWithSpacing
    val buttonPositionY = textPositionY + textHeightWithSpacing
    val layoutHeight = titleHeightWithSpacing + textHeightWithSpacing + buttonHeightWithSpacing

    val layoutWidth = max(
        buttonPlaceable?.width ?: 0,
        max(titlePlaceable?.width ?: 0, textPlaceable?.width ?: 0)
    )
}

@Composable
internal fun ColumnScope.AlertDialogBaselineLayout(
    modifier: Modifier = Modifier,
    title: @Composable (() -> Unit)?,
    text: @Composable (() -> Unit)?,
    button: @Composable (() -> Unit)?,
    offset: TextUnit
) {
    Layout(
        {
            title?.let { title ->
                Box(
                    Modifier
                        .layoutId("title")
                        .align(Alignment.Start)
                ) {
                    title()
                }
            }
            text?.let { text ->
                Box(
                    Modifier
                        .layoutId("text")
                        .align(Alignment.Start)
                ) {
                    text()
                }
            }
            button?.let { button ->
                Box(
                    Modifier
                        .layoutId("buttons")
                        .align(Alignment.Start)
                ) {
                    button()
                }
            }
        },
        modifier.weight(1f, false)
    ) { measurables, constraints ->
        val calculator = AlertDialogBaselineCalculator(measurables, constraints, offset.roundToPx())
        layout(calculator.layoutWidth, calculator.layoutHeight) {
            calculator.titlePlaceable?.place(0, calculator.titlePositionY)
            calculator.textPlaceable?.place(0, calculator.textPositionY)
            calculator.buttonPlaceable?.place(0, calculator.buttonPositionY)
        }
    }
}

@Composable
internal fun AlertDialogContent(
    modifier: Modifier = Modifier,
    title: (@Composable () -> Unit)? = null,
    text: @Composable (() -> Unit)? = null,
    buttons: @Composable (() -> Unit)? = null,
    offset: TextUnit = 0.sp,
    shape: Shape = MaterialTheme.shapes.medium,
    backgroundColor: Color = MaterialTheme.colors.surface,
    contentColor: Color = contentColorFor(backgroundColor),
) {
    Surface(
        shape = shape,
        color = backgroundColor,
        contentColor = contentColor
    ) {
        Column {
            AlertDialogBaselineLayout(
                modifier = modifier,
                title = title?.let {
                    @Composable {
                        CompositionLocalProvider(LocalContentAlpha provides ContentAlpha.high) {
                            val textStyle = MaterialTheme.typography.subtitle1
                            ProvideTextStyle(textStyle, title)
                        }
                    }
                },
                text = text?.let {
                    @Composable {
                        CompositionLocalProvider(
                            LocalContentAlpha provides ContentAlpha.medium
                        ) {
                            val textStyle = MaterialTheme.typography.body2
                            ProvideTextStyle(textStyle, text)
                        }
                    }
                },
                button = buttons,
                offset = offset
            )
        }
    }
}

@Composable
@Suppress("ReusedModifierInstance")
fun AlertDialog(
    onDismissRequest: () -> Unit,
    modifier: Modifier = Modifier.padding (all=26.dp),
    title: (@Composable () -> Unit)? = null,
    text: @Composable (() -> Unit)? = null,
    buttons: @Composable (() -> Unit)? = null,
    offset: TextUnit = 28.sp,
    shape: Shape = MaterialTheme.shapes.medium,
    backgroundColor: Color = MaterialTheme.colors.surface,
    contentColor: Color = contentColorFor(backgroundColor),
    properties: DialogProperties = DialogProperties()
) {
    Dialog(
        onDismissRequest = onDismissRequest,
        properties = properties
    ) {
        AlertDialogContent(
            modifier = modifier,
            title = title,
            text = text,
            buttons = buttons,
            offset = offset,
            shape = shape,
            backgroundColor = backgroundColor,
            contentColor = contentColor
        )
    }
}

@AnimealPreview
@Composable
private fun AnimealAlertDialogFullPreview() {
    AnimealTheme {
        AlertDialog(
            title = {
                Text(
                    text = "Title",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.h6,
                )
            },
            text = {
                Text(
                    text = "Text",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.h6,
                )
            },
            buttons = {
                AnimealButton(
                    text = "Button Text",
                    onClick = {}
                )
            },
            onDismissRequest = {}
        )
    }
}

@AnimealPreview
@Composable
private fun AnimealAlertDialogTitleTextPreview() {
    AnimealTheme {
        AlertDialog(
            title = {
                Text(
                    text = "Title",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.h6,
                )
            },
            text = {
                Text(
                    text = "Text",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.h6,
                )
            },
            onDismissRequest = {}
        )
    }
}

@AnimealPreview
@Composable
private fun AnimealAlertDialogTitleButtonsPreview() {
    AnimealTheme {
        AlertDialog(
            title = {
                Text(
                    text = "Title",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.h6,
                )
            },
            buttons = {
                AnimealButton(
                    text = "Button Text",
                    onClick = {}
                )
            },
            onDismissRequest = {}
        )
    }
}

@AnimealPreview
@Composable
private fun AnimealAlertDialogTextButtonsPreview() {
    AnimealTheme {
        AlertDialog(
            text = {
                Text(
                    text = "Text",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.h6,
                )
            },
            buttons = {
                AnimealButton(
                    text = "Button Text",
                    onClick = {}
                )
            },
            onDismissRequest = {}
        )
    }
}

@AnimealPreview
@Composable
private fun AnimealAlertDialogTitlePreview() {
    AnimealTheme {
        AlertDialog(
            title = {
                Text(
                    text = "Title",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.h6,
                )
            },
            onDismissRequest = {}
        )
    }
}

@AnimealPreview
@Composable
private fun AnimealAlertDialogTextPreview() {
    AnimealTheme {
        AlertDialog(
            text = {
                Text(
                    text = "Text",
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.h6,
                )
            },
            onDismissRequest = {}
        )
    }
}

@AnimealPreview
@Composable
private fun AnimealAlertDialogButtonsPreview() {
    AnimealTheme {
        AlertDialog(
            buttons = {
                AnimealButton(
                    text = "Button Text",
                    onClick = {}
                )
            },
            onDismissRequest = {}
        )
    }
}
