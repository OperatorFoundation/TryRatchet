package org.operatorfoundation.tryratchet

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.operatorfoundation.aes.Ciphertext
import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.ratchet.PlaintextMessage
import org.operatorfoundation.ratchet.PlaintextMessageType
import org.operatorfoundation.ratchet.Ratchet
import org.operatorfoundation.ratchet.RatchetState

class MainViewModel : ViewModel()
{

    // UI-friendly representation of a party's crypto state
    data class PartyState(
        val publicKey: ByteArray,
        val rootKey: ByteArray,
        val chainKey: ByteArray?,
        val messageKey: ByteArray?,
        val ratchetStep: Int
    ) {
        fun publicKeyHexTruncated() = publicKey.toHexTruncated()
        fun rootKeyHexTruncated() = rootKey.toHexTruncated()
        fun chainKeyHexTruncated() = chainKey?.toHexTruncated() ?: "—"
        fun messageKeyHexTruncated() = messageKey?.toHexTruncated() ?: "—"
        fun publicKeyHex() = publicKey.toHex()
        fun rootKeyHex() = rootKey.toHex()
        fun chainKeyHex() = chainKey?.toHex() ?: "—"
        fun messageKeyHex() = messageKey?.toHex() ?: "—"

        private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

        private fun ByteArray.toHexTruncated(maxLen: Int = 8): String
        {
            val hex = joinToString("") { "%02x".format(it) }

            return if (hex.length > maxLen) "${hex.take(maxLen)}..." else hex
        }

        override fun equals(other: Any?): Boolean
        {
            if (this === other) return true
            if (other !is PartyState) return false

            return publicKey.contentEquals(other.publicKey) &&
                    rootKey.contentEquals(other.rootKey) &&
                    ratchetStep == other.ratchetStep
        }

        override fun hashCode(): Int
        {
            var result = publicKey.contentHashCode()
            result = 31 * result + rootKey.contentHashCode()
            result = 31 * result + ratchetStep

            return result
        }
    }

    data class UiState(
        val isStarted: Boolean = false,
        val aliceState: PartyState? = null,
        val bobState: PartyState? = null,
        val messages: List<ChatMessage> = emptyList()
    )

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    // Internal ratchet state
    private var aliceKeypair: Curve25519KeyPair? = null
    private var bobKeypair: Curve25519KeyPair? = null
    private var aliceRatchetState: RatchetState? = null
    private var bobRatchetState: RatchetState? = null
    private var aliceHasRatcheted = false
    private var bobHasRatcheted = false
    private var messageIdCounter = 0L

    /**
     * Initialize both parties with fresh keypairs and derive initial root keys.
     */
    fun start()
    {
        aliceKeypair = MADH.generateKeypair()
        bobKeypair = MADH.generateKeypair()

        aliceRatchetState = Ratchet.newRatchetState(aliceKeypair!!, bobKeypair!!.publicKey)
        bobRatchetState = Ratchet.newRatchetState(bobKeypair!!, aliceKeypair!!.publicKey)

        aliceHasRatcheted = false
        bobHasRatcheted = false
        messageIdCounter = 0L

        _uiState.update {
            UiState(
                isStarted = true,
                aliceState = aliceRatchetState?.toPartyState(aliceKeypair!!),
                bobState = bobRatchetState?.toPartyState(bobKeypair!!),
                messages = emptyList()
            )
        }
    }

    /**
     * Reset everything back to initial state.
     */
    fun reset()
    {
        aliceKeypair = null
        bobKeypair = null
        aliceRatchetState = null
        bobRatchetState = null
        aliceHasRatcheted = false
        bobHasRatcheted = false
        messageIdCounter = 0L

        _uiState.value = UiState()
    }

    /**
     * Send a message from Alice.
     */
    fun sendFromAlice(plaintext: String) {
        sendMessage(plaintext, ChatMessage.Sender.ALICE)
    }

    /**
     * Send a message from Bob.
     */
    fun sendFromBob(plaintext: String) {
        sendMessage(plaintext, ChatMessage.Sender.BOB)
    }

    private fun sendMessage(plaintext: String, sender: ChatMessage.Sender)
    {
        val isAlice = sender == ChatMessage.Sender.ALICE

        var senderState = if (isAlice) aliceRatchetState!! else bobRatchetState!!

        // Determine ratchet type
        val needsDHRatchet = if (isAlice) !aliceHasRatcheted else !bobHasRatcheted
        val ratchetType: ChatMessage.RatchetType

        if (needsDHRatchet)
        {
            val newRemoteEphemeralKey = MADH.generateKeypair().publicKey
            senderState = Ratchet.ratchetWithNewKey(senderState, newRemoteEphemeralKey)
            ratchetType = ChatMessage.RatchetType.DH
            if (isAlice) aliceHasRatcheted = true else bobHasRatcheted = true
        }
        else
        {
            senderState = Ratchet.ratchetWithoutNewKey(senderState)
            ratchetType = ChatMessage.RatchetType.SYMMETRIC
        }

        if (isAlice) aliceRatchetState = senderState
        else bobRatchetState = senderState

        // Encrypt
        val plaintextMessage = PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = plaintext.toByteArray(Charsets.UTF_8)
        )

        val ciphertext: Ciphertext = Ratchet.encrypt(senderState.messageKey!!, plaintextMessage)

        val chatMessage = ChatMessage(
            id = ++messageIdCounter,
            sender = sender,
            plaintext = plaintext,
            nonce = ciphertext.nonce.bytes,
            ciphertext = ciphertext.encrypted,
            tag = ciphertext.tag,
            ratchetType = ratchetType
        )

        _uiState.update { current ->
            current.copy(
                aliceState = aliceRatchetState?.toPartyState(aliceKeypair!!),
                bobState = bobRatchetState?.toPartyState(bobKeypair!!),
                messages = current.messages + chatMessage
            )
        }
    }

    private fun RatchetState.toPartyState(keypair: Curve25519KeyPair): PartyState
    {
        return PartyState(
            publicKey = keypair.publicKey.bytes,
            rootKey = rootKey.bytes,
            chainKey = chainKey?.bytes,
            messageKey = messageKey?.bytes,
            ratchetStep = messageNumber
        )
    }
}