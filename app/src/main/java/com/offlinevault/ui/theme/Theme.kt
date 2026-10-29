package com.offlinevault.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val LightColors = lightColorScheme(
    primary = TextPrimary,
    onPrimary = Color.White,
    primaryContainer = VaultSurfaceVariant,
    onPrimaryContainer = TextPrimary,
    secondary = SafetyBlue,
    secondaryContainer = Color(0xFFE8EEFA),
    onSecondaryContainer = Color(0xFF163F90),
    tertiary = RiskMedium,
    background = VaultBackground,
    onBackground = TextPrimary,
    surface = VaultSurface,
    onSurface = TextPrimary,
    surfaceVariant = VaultSurfaceVariant,
    onSurfaceVariant = TextSecondary,
    surfaceTint = TextPrimary,
    surfaceDim = Color(0xFFDCDFE5),
    surfaceBright = VaultSurface,
    surfaceContainerLowest = VaultSurface,
    surfaceContainerLow = VaultBackground,
    surfaceContainer = VaultSurfaceVariant,
    surfaceContainerHigh = Color(0xFFE9ECF1),
    surfaceContainerHighest = Color(0xFFE3E6EC),
    inverseSurface = TextPrimary,
    inverseOnSurface = Color.White,
    inversePrimary = Color(0xFFE3E6EC),
    outline = VaultOutline,
    outlineVariant = Color(0xFFE3E6EC),
    error = RiskHigh,
    onError = Color.White
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFF2F3F5),
    onPrimary = Color(0xFF17181B),
    primaryContainer = Color(0xFF292B30),
    onPrimaryContainer = Color(0xFFF2F3F5),
    secondary = Color(0xFFA9C7FF),
    secondaryContainer = Color(0xFF1D3153),
    onSecondaryContainer = Color(0xFFD6E4FF),
    tertiary = Color(0xFFE8BD73),
    background = Color(0xFF101113),
    onBackground = Color(0xFFF2F3F5),
    surface = Color(0xFF1A1B1F),
    onSurface = Color(0xFFF2F3F5),
    surfaceVariant = Color(0xFF25272C),
    onSurfaceVariant = Color(0xFFB6BBC5),
    surfaceTint = Color(0xFFF2F3F5),
    surfaceDim = Color(0xFF101113),
    surfaceBright = Color(0xFF34373E),
    surfaceContainerLowest = Color(0xFF101113),
    surfaceContainerLow = Color(0xFF17181B),
    surfaceContainer = Color(0xFF1A1B1F),
    surfaceContainerHigh = Color(0xFF25272C),
    surfaceContainerHighest = Color(0xFF34373E),
    inverseSurface = Color(0xFFF2F3F5),
    inverseOnSurface = Color(0xFF17181B),
    inversePrimary = TextPrimary,
    outline = Color(0xFF737986),
    outlineVariant = Color(0xFF34373E),
    error = Color(0xFFFFAABA),
    onError = Color(0xFF590018)
)

private val VaultShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp)
)

@Composable
fun OfflineVaultTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        typography = VaultTypography,
        shapes = VaultShapes,
        content = content
    )
}
