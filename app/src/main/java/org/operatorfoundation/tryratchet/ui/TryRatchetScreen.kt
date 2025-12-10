package org.operatorfoundation.tryratchet.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import org.operatorfoundation.tryratchet.ChatMessage
import org.operatorfoundation.tryratchet.CryptoTestResults
import org.operatorfoundation.tryratchet.MainViewModel
import org.operatorfoundation.tryratchet.R
import org.operatorfoundation.tryratchet.ui.theme.*

@Composable
fun TryRatchetScreen(
    modifier: Modifier = Modifier,
    viewModel: MainViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val testResults by viewModel.testResults.collectAsState()
    var handshakeExpanded by remember { mutableStateOf(true) }
    var fullValueDialog by remember { mutableStateOf<Pair<String, String>?>(null) }
    var messageText by remember { mutableStateOf("") }
    var cryptoStateExpanded by remember { mutableStateOf(false) }
    var textFieldFocused by remember { mutableStateOf(false) }
    val keyboardController = LocalSoftwareKeyboardController.current

    if (testResults != null)
    {
        TestResultsSheet(
            results = testResults!!,
            onDismiss = { viewModel.clearTestResults() }
        )
    }
    else
    {
        Column(
            modifier = modifier
                .fillMaxSize()
                .background(BackgroundPrimary)
        )
        {
            // Header
            Header(
                isStarted = uiState.isStarted,
                onStart = { viewModel.start() },
                onReset = { viewModel.reset() },
                onRunTests = { viewModel.runTests() }
            )

            // MADH Handshake Panel
            if (uiState.isStarted && uiState.handshakeState != null)
            {
                MADHHandshakePanel(
                    handshakeState = uiState.handshakeState!!,
                    expanded = handshakeExpanded,
                    onToggle = { handshakeExpanded = !handshakeExpanded }
                )
                HorizontalDivider(color = Divider, thickness = 1.dp)
            }

            // Show initial root key agreement status
            if (uiState.isStarted && uiState.initialRootKeysMatch != null)
            {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(if (uiState.initialRootKeysMatch!!) KeyMessage.copy(alpha = 0.1f) else Color(0xFFEF4444).copy(alpha = 0.1f))
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        painter = painterResource(
                            if (uiState.initialRootKeysMatch!!) R.drawable.ic_check else R.drawable.ic_error
                        ),
                        contentDescription = null,
                        tint = if (uiState.initialRootKeysMatch!!) KeyMessage else Color(0xFFEF4444),
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = if (uiState.initialRootKeysMatch!!) {
                            "Initial root keys match ✓"
                        } else {
                            "Initial root keys DO NOT match ✗"
                        },
                        color = if (uiState.initialRootKeysMatch!!) KeyMessage else Color(0xFFEF4444),
                        fontSize = 12.sp
                    )
                }
            }

            HorizontalDivider(color = Divider, thickness = 1.dp)

            // Crypto State Panel
            if (uiState.isStarted) {
                CryptoStatePanel(
                    aliceState = uiState.aliceState,
                    bobState = uiState.bobState,
                    expanded = cryptoStateExpanded,
                    onToggle = { cryptoStateExpanded = !cryptoStateExpanded },
                    onShowFullValue = { label, value -> fullValueDialog = Pair(label, value) }
                )
                HorizontalDivider(color = Divider, thickness = 1.dp)
            }

            // Chat area
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                when {
                    !uiState.isStarted -> EmptyStateNotStarted()
                    uiState.messages.isEmpty() -> EmptyStateStarted()
                    else -> MessageList(messages = uiState.messages)
                }
            }

            // Input area
            if (uiState.isStarted)
            {
                Column(modifier = Modifier.imePadding()) {
                    HorizontalDivider(color = Divider, thickness = 1.dp)
                    InputArea(
                        messageText = messageText,
                        onMessageChange = { messageText = it },
                        onSendAlice = {
                            if (messageText.isNotBlank()) {
                                viewModel.sendFromAlice(messageText)
                                messageText = ""
                                keyboardController?.hide()
                            }
                        },
                        onSendBob = {
                            if (messageText.isNotBlank()) {
                                viewModel.sendFromBob(messageText)
                                messageText = ""
                                keyboardController?.hide()
                            }
                        },
                        onFocusChanged = { focused ->
                            if (focused)
                            {
                                cryptoStateExpanded = false
                                handshakeExpanded = false
                            }
                        }
                    )
                }
            }

            fullValueDialog?.let { (label, value) ->
                AlertDialog(
                    onDismissRequest = { fullValueDialog = null },
                    title = { Text(label) },
                    text = {
                        SelectionContainer() {
                            Text(
                                text = value,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp
                            )
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { fullValueDialog = null }) {
                            Text("Close")
                        }
                    }
                )
            }
        }
    }
}

@Composable
private fun Header(
    isStarted: Boolean,
    onStart: () -> Unit,
    onReset: () -> Unit,
    onRunTests: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_lock),
            contentDescription = null,
            tint = AlicePrimary,
            modifier = Modifier.size(28.dp)
        )

        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 12.dp)
        ) {
            Text(
                text = "TryRatchet",
                color = TextPrimary,
                fontSize = 18.sp,
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = "Double Ratchet Demo",
                color = TextTertiary,
                fontSize = 12.sp
            )
        }

        Button(
            onClick = onRunTests,
            colors = ButtonDefaults.buttonColors(containerColor = KeyChain)
        ) {
            Text("Test")
        }

        if (!isStarted)
        {
            Button(
                onClick = onStart,
                colors = ButtonDefaults.buttonColors(containerColor = AlicePrimary)
            ) {
                Text("Start")
            }
        }
        else
        {
            Button(
                onClick = onReset,
                colors = ButtonDefaults.buttonColors(containerColor = BackgroundTertiary)
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_reset),
                    contentDescription = null,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(Modifier.width(4.dp))
                Text("Reset")
            }
        }
    }
}

@Composable
private fun CryptoStatePanel(
    aliceState: MainViewModel.PartyState?,
    bobState: MainViewModel.PartyState?,
    expanded: Boolean,
    onToggle: () -> Unit,
    onShowFullValue: (label: String, value: String) -> Unit
) {
    Column {
        // Toggle header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onToggle() }
                .padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Crypto State",
                color = TextSecondary,
                fontSize = 14.sp
            )
            Icon(
                painter = painterResource(
                    if (expanded) R.drawable.ic_chevron_up else R.drawable.ic_chevron_down
                ),
                contentDescription = null,
                tint = TextSecondary,
                modifier = Modifier.size(20.dp)
            )
        }

        // Expandable content
        AnimatedVisibility(visible = expanded) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp)
                    .padding(bottom = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                aliceState?.let {
                    PartyStateCard(
                        name = "Alice",
                        state = it,
                        accentColor = AlicePrimary,
                        modifier = Modifier.weight(1f),
                        onShowFullValue = onShowFullValue
                    )
                }
                bobState?.let {
                    PartyStateCard(
                        name = "Bob",
                        state = it,
                        accentColor = BobPrimary,
                        modifier = Modifier.weight(1f),
                        onShowFullValue = onShowFullValue
                    )
                }
            }
        }
    }
}

@Composable
private fun PartyStateCard(
    name: String,
    state: MainViewModel.PartyState,
    accentColor: Color,
    modifier: Modifier = Modifier,
    onShowFullValue: (label: String, value: String) -> Unit
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(BackgroundSecondary.copy(alpha = 0.5f))
            .padding(12.dp)
    ) {
        Text(
            text = name,
            color = accentColor,
            fontSize = 14.sp,
            style = MaterialTheme.typography.titleSmall
        )

        Spacer(Modifier.height(8.dp))

        KeyValueRow(
            label = "Public Key",
            value = state.publicKeyHexTruncated(),
            valueColor = accentColor,
            onTap = { onShowFullValue("Public Key", state.publicKeyHex()) }
        )

        KeyValueRow(
            label = "Root Key",
            value = state.rootKeyHexTruncated(),
            valueColor = KeyRoot,
            onTap = { onShowFullValue("Root Key", state.rootKeyHex())}
            )

        KeyValueRow(
            label = "Chain Key",
            value = state.chainKeyHexTruncated(),
            valueColor = KeyChain,
            onTap = { onShowFullValue("Chain Key", state.chainKeyHex()) }
            )

        KeyValueRow(
            label = "Message Key",
            value = state.messageKeyHexTruncated(),
            valueColor = KeyMessage,
            onTap = { onShowFullValue("Message Key", state.messageKeyHex()) }
            )

        HorizontalDivider(
            color = Divider,
            thickness = 1.dp,
            modifier = Modifier.padding(vertical = 8.dp)
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "Ratchet Step",
                color = TextTertiary,
                fontSize = 11.sp
            )
            Text(
                text = state.ratchetStep.toString(),
                color = accentColor,
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}

@Composable
private fun KeyValueRow(
    label: String,
    value: String,
    valueColor: Color,
    onTap: (() -> Unit?)? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            color = TextTertiary,
            fontSize = 11.sp
        )
        Text(
            text = value,
            color = valueColor,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier
                .background(BackgroundSecondary, RoundedCornerShape(4.dp))
                .then( if (onTap != null) Modifier.clickable { onTap() } else Modifier)
                .padding(horizontal = 8.dp, vertical = 2.dp)
        )
    }
}

@Composable
private fun EmptyStateNotStarted() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                painter = painterResource(R.drawable.ic_lock),
                contentDescription = null,
                tint = TextTertiary.copy(alpha = 0.3f),
                modifier = Modifier.size(56.dp)
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = "Tap \"Start\" to initialize\nAlice and Bob's keys",
                color = TextTertiary,
                fontSize = 14.sp,
                lineHeight = 20.sp
            )
        }
    }
}

@Composable
private fun EmptyStateStarted() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = "Type a message and choose\nwho sends it",
            color = TextTertiary,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )
    }
}

@Composable
private fun MessageList(messages: List<ChatMessage>) {
    val listState = rememberLazyListState()
    val coroutineScope = rememberCoroutineScope()

    // Auto-scroll to bottom when new message added
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            coroutineScope.launch {
                listState.animateScrollToItem(messages.size - 1)
            }
        }
    }

    LazyColumn(
        state = listState,
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(messages, key = { it.id }) { message ->
            MessageBubble(message = message)
        }
    }
}

@Composable
private fun MessageBubble(message: ChatMessage) {
    val isAlice = message.sender == ChatMessage.Sender.ALICE
    var expanded by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (isAlice) Alignment.Start else Alignment.End
    ) {
        // Message bubble
        Text(
            text = message.plaintext,
            color = TextPrimary,
            fontSize = 14.sp,
            modifier = Modifier
                .clip(
                    RoundedCornerShape(
                        topStart = 18.dp,
                        topEnd = 18.dp,
                        bottomStart = if (isAlice) 4.dp else 18.dp,
                        bottomEnd = if (isAlice) 18.dp else 4.dp
                    )
                )
                .background(if (isAlice) AlicePrimary else BobPrimary)
                .padding(horizontal = 16.dp, vertical = 10.dp)
                .widthIn(max = 280.dp)
        )

        // Ratchet type
        Row(
            modifier = Modifier
                .clickable { expanded = !expanded }
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = if (message.ratchetType == ChatMessage.RatchetType.DH) "DH ratchet" else "Symmetric ratchet",
                color = TextTertiary,
                fontSize = 11.sp
            )
            Icon(
                painter = painterResource(
                    if (expanded) R.drawable.ic_chevron_up else R.drawable.ic_chevron_down
                ),
                contentDescription = null,
                tint = TextTertiary,
                modifier = Modifier.size(14.dp)
            )
        }

        // Test status indicator
        Row(
            modifier = Modifier.padding(top = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            val passed = message.testPassed()
            Icon(
                painter = painterResource(
                    if (passed) R.drawable.ic_check else R.drawable.ic_error
                ),
                contentDescription = null,
                tint = if (passed) KeyMessage else Color(0xFFEF4444),
                modifier = Modifier.size(12.dp)
            )
            Text(
                text = if (passed) "Decrypt OK" else "Decrypt FAILED",
                color = if (passed) KeyMessage else Color(0xFFEF4444),
                fontSize = 10.sp
            )
        }

        // Crypto details
        AnimatedVisibility(visible = expanded) {
            Column(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(BackgroundSecondary.copy(alpha = 0.8f))
                    .padding(10.dp)
            ) {
                CryptoDetailRow("nonce:", message.nonceHex(), KeyNonce)
                CryptoDetailRow("ciphertext:", message.ciphertextHexTruncated(), KeyCiphertext)
                CryptoDetailRow("tag:", message.tagHex(), KeyTag)

                // Test results
                CryptoDetailRow(
                    "keys match:",
                    if (message.keysMatched) "yes" else "NO",
                    if (message.keysMatched) KeyMessage else Color(0xFFEF4444)
                )
                CryptoDetailRow(
                    "decrypt:",
                    if (message.decryptionSuccess) "success" else "FAILED",
                    if (message.decryptionSuccess) KeyMessage else Color(0xFFEF4444)
                )

                if (message.decryptedText != null) {
                    CryptoDetailRow("output:", "\"${message.decryptedText}\"", TextSecondary)
                }
            }
        }
    }
}

@Composable
private fun CryptoDetailRow(label: String, value: String, valueColor: Color) {
    Row(modifier = Modifier.padding(vertical = 2.dp)) {
        Text(
            text = label,
            color = TextTertiary,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace
        )
        Spacer(Modifier.width(4.dp))
        Text(
            text = value,
            color = valueColor,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
private fun InputArea(
    messageText: String,
    onMessageChange: (String) -> Unit,
    onSendAlice: () -> Unit,
    onSendBob: () -> Unit,
    onFocusChanged: (Boolean) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
    ) {
        OutlinedTextField(
            value = messageText,
            onValueChange = onMessageChange,
            placeholder = { Text("Type a message...", color = TextTertiary) },
            modifier = Modifier
                .fillMaxWidth()
                .onFocusChanged { onFocusChanged(it.isFocused) },
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = BackgroundSecondary,
                unfocusedContainerColor = BackgroundSecondary,
                focusedBorderColor = AlicePrimary,
                unfocusedBorderColor = Color.Transparent,
                cursorColor = AlicePrimary,
                focusedTextColor = TextPrimary,
                unfocusedTextColor = TextPrimary
            ),
            shape = RoundedCornerShape(12.dp),
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { onSendAlice() })
        )

        Spacer(Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = onSendAlice,
                enabled = messageText.isNotBlank(),
                modifier = Modifier
                    .weight(1f)
                    .height(52.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = AlicePrimary,
                    disabledContainerColor = BackgroundTertiary
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text("Alice", fontSize = 16.sp)
            }

            Button(
                onClick = onSendBob,
                enabled = messageText.isNotBlank(),
                modifier = Modifier
                    .weight(1f)
                    .height(52.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = BobPrimary,
                    disabledContainerColor = BackgroundTertiary
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text("Bob", fontSize = 16.sp)
            }
        }
    }
}

@Composable
private fun TestResultsSheet(
    results: CryptoTestResults,
    onDismiss: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BackgroundPrimary)
            .padding(16.dp)
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Test Results",
                color = TextPrimary,
                fontSize = 20.sp,
                style = MaterialTheme.typography.titleLarge
            )
            IconButton(onClick = onDismiss) {
                Icon(
                    painter = painterResource(R.drawable.ic_close),
                    contentDescription = "Close",
                    tint = TextSecondary
                )
            }
        }

        // Summary
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "✓ ${results.passCount} passed",
                color = KeyMessage,
                fontSize = 14.sp
            )
            Text(
                text = "✗ ${results.failCount} failed",
                color = if (results.failCount > 0) Color(0xFFEF4444) else TextTertiary,
                fontSize = 14.sp
            )
        }

        HorizontalDivider(color = Divider)

        // Results list
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(vertical = 12.dp)
        ) {
            items(results.tests) { test ->
                TestResultItem(test)
            }
        }
    }
}

@Composable
private fun TestResultItem(test: CryptoTestResults.TestResult) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(BackgroundSecondary)
            .padding(12.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = if (test.passed) "✓" else "✗",
                color = if (test.passed) KeyMessage else Color(0xFFEF4444),
                fontSize = 14.sp
            )
            Text(
                text = test.name,
                color = TextPrimary,
                fontSize = 14.sp
            )
        }

        Text(
            text = test.category.name.replace("_", " "),
            color = TextTertiary,
            fontSize = 10.sp,
            modifier = Modifier.padding(start = 22.dp, top = 2.dp)
        )

        Text(
            text = test.details,
            color = TextSecondary,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.padding(start = 22.dp, top = 4.dp)
        )

        if (test.errorMessage != null) {
            Text(
                text = "Error: ${test.errorMessage}",
                color = Color(0xFFEF4444),
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(start = 22.dp, top = 4.dp)
            )
        }
    }
}

/**
 * MADH Handshake verification panel.
 *
 * Displays the confirmation codes that both parties compute independently.
 * In a real application, users would compare these codes out-of-band
 * (e.g., reading them aloud over a phone call) to verify the connection
 * hasn't been intercepted by a man-in-the-middle.
 */
@Composable
private fun MADHHandshakePanel(
    handshakeState: MainViewModel.HandshakeState,
    expanded: Boolean,
    onToggle: () -> Unit
) {
    Column {
        // Toggle header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onToggle() }
                .padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "MADH Handshake",
                    color = TextSecondary,
                    fontSize = 14.sp
                )

                // Status indicator in header
                Icon(
                    painter = painterResource(
                        if (handshakeState.codesMatch) R.drawable.ic_check else R.drawable.ic_error
                    ),
                    contentDescription = null,
                    tint = if (handshakeState.codesMatch) KeyMessage else Color(0xFFEF4444),
                    modifier = Modifier.size(16.dp)
                )
            }

            Icon(
                painter = painterResource(
                    if (expanded) R.drawable.ic_chevron_up else R.drawable.ic_chevron_down
                ),
                contentDescription = null,
                tint = TextSecondary,
                modifier = Modifier.size(20.dp)
            )
        }

        // Expandable content
        AnimatedVisibility(visible = expanded) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .padding(bottom = 16.dp)
            ) {
                // Confirmation codes display
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    ConfirmationCodeCard(
                        partyName = "Alice",
                        code = handshakeState.aliceCode,
                        accentColor = AlicePrimary,
                        modifier = Modifier.weight(1f)
                    )

                    ConfirmationCodeCard(
                        partyName = "Bob",
                        code = handshakeState.bobCode,
                        accentColor = BobPrimary,
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(Modifier.height(12.dp))

                // Verification status
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(BackgroundSecondary.copy(alpha = 0.5f))
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Commitment verification
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            painter = painterResource(
                                if (handshakeState.commitmentVerified) R.drawable.ic_check else R.drawable.ic_error
                            ),
                            contentDescription = null,
                            tint = if (handshakeState.commitmentVerified) KeyMessage else Color(0xFFEF4444),
                            modifier = Modifier.size(14.dp)
                        )
                        Text(
                            text = if (handshakeState.commitmentVerified) {
                                "Public key commitment verified"
                            } else {
                                "Public key commitment FAILED"
                            },
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }

                    // Codes match verification
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            painter = painterResource(
                                if (handshakeState.codesMatch) R.drawable.ic_check else R.drawable.ic_error
                            ),
                            contentDescription = null,
                            tint = if (handshakeState.codesMatch) KeyMessage else Color(0xFFEF4444),
                            modifier = Modifier.size(14.dp)
                        )
                        Text(
                            text = if (handshakeState.codesMatch) {
                                "Confirmation codes match"
                            } else {
                                "Confirmation codes DO NOT match"
                            },
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }
                }

                // Explanatory note
                Text(
                    text = "In a real app, users compare these codes out-of-band (e.g., voice call) to verify no man-in-the-middle attack.",
                    color = TextTertiary,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }
    }
}

/**
 * Card displaying a party's confirmation code.
 */
@Composable
private fun ConfirmationCodeCard(
    partyName: String,
    code: String,
    accentColor: Color,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(BackgroundSecondary.copy(alpha = 0.5f))
            .padding(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = partyName,
            color = accentColor,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium
        )

        Spacer(Modifier.height(8.dp))

        Text(
            text = formatConfirmationCode(code),
            color = TextPrimary,
            fontSize = 20.sp,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            letterSpacing = 2.sp
        )
    }
}

/**
 * Format confirmation code for readability.
 * Groups digits for easier comparison.
 */
private fun formatConfirmationCode(code: String): String
{
    return when {
        code.length <= 4 -> code
        code.length <= 6 -> "${code.take(3)} ${code.drop(3)}"
        code.length <= 8 -> "${code.take(4)} ${code.drop(4)}"
        else -> code.chunked(4).joinToString(" ")
    }
}