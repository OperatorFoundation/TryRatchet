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
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import org.operatorfoundation.tryratchet.ChatMessage
import org.operatorfoundation.tryratchet.MainViewModel
import org.operatorfoundation.tryratchet.R
import org.operatorfoundation.tryratchet.ui.theme.*

@Composable
fun TryRatchetScreen(
    modifier: Modifier = Modifier,
    viewModel: MainViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    var messageText by remember { mutableStateOf("") }
    var cryptoStateExpanded by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(BackgroundPrimary)
    ) {
        // Header
        Header(
            isStarted = uiState.isStarted,
            onStart = { viewModel.start() },
            onReset = { viewModel.reset() }
        )

        HorizontalDivider(color = Divider, thickness = 1.dp)

        // Crypto State Panel
        if (uiState.isStarted) {
            CryptoStatePanel(
                aliceState = uiState.aliceState,
                bobState = uiState.bobState,
                expanded = cryptoStateExpanded,
                onToggle = { cryptoStateExpanded = !cryptoStateExpanded }
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
            HorizontalDivider(color = Divider, thickness = 1.dp)
            InputArea(
                messageText = messageText,
                onMessageChange = { messageText = it },
                onSendAlice = {
                    if (messageText.isNotBlank()) {
                        viewModel.sendFromAlice(messageText)
                        messageText = ""
                    }
                },
                onSendBob = {
                    if (messageText.isNotBlank()) {
                        viewModel.sendFromBob(messageText)
                        messageText = ""
                    }
                }
            )
        }
    }
}

@Composable
private fun Header(
    isStarted: Boolean,
    onStart: () -> Unit,
    onReset: () -> Unit
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

        if (!isStarted) {
            Button(
                onClick = onStart,
                colors = ButtonDefaults.buttonColors(containerColor = AlicePrimary)
            ) {
                Text("Start")
            }
        } else {
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
                        modifier = Modifier.weight(1f)
                    )
                }
                bobState?.let {
                    PartyStateCard(
                        name = "Bob",
                        state = it,
                        accentColor = BobPrimary,
                        modifier = Modifier.weight(1f)
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
    modifier: Modifier = Modifier
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

        KeyValueRow("Public Key", state.publicKeyHex(), accentColor)
        KeyValueRow("Root Key", state.rootKeyHex(), KeyRoot)
        KeyValueRow("Chain Key", state.chainKeyHex(), KeyChain)
        KeyValueRow("Message Key", state.messageKeyHex(), KeyMessage)

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
private fun KeyValueRow(label: String, value: String, valueColor: Color) {
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

        // Ratchet type toggle
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
    onSendBob: () -> Unit
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
            modifier = Modifier.fillMaxWidth(),
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