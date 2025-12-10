package org.operatorfoundation.tryratchet.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Base colors
val BackgroundPrimary = Color(0xFF111827)
val BackgroundSecondary = Color(0xFF1F2937)
val BackgroundTertiary = Color(0xFF374151)

val TextPrimary = Color(0xFFFFFFFF)
val TextSecondary = Color(0xFF9CA3AF)
val TextTertiary = Color(0xFF6B7280)

// Alice (teal)
val AlicePrimary = Color(0xFF0D9488)
val AliceLight = Color(0xFF14B8A6)

// Bob (orange)
val BobPrimary = Color(0xFFEA580C)
val BobLight = Color(0xFFF97316)

// Crypto state colors
val KeyRoot = Color(0xFFFBBF24)
val KeyChain = Color(0xFFA855F7)
val KeyMessage = Color(0xFF22C55E)
val KeyNonce = Color(0xFF3B82F6)
val KeyCiphertext = Color(0xFFEC4899)
val KeyTag = Color(0xFFF59E0B)

val Divider = Color(0xFF374151)

private val DarkColorScheme = darkColorScheme(
    primary = AlicePrimary,
    secondary = BobPrimary,
    background = BackgroundPrimary,
    surface = BackgroundSecondary,
    onPrimary = TextPrimary,
    onSecondary = TextPrimary,
    onBackground = TextPrimary,
    onSurface = TextPrimary
)

@Composable
fun TryRatchetTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}