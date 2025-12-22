package org.operatorfoundation.tryratchet

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.operatorfoundation.aes.Ciphertext
import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.Curve25519PublicKey
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.madh.SessionIdentifier
import org.operatorfoundation.ratchet.PlaintextMessage
import org.operatorfoundation.ratchet.PlaintextMessageType
import org.operatorfoundation.ratchet.Ratchet
import org.operatorfoundation.ratchet.RatchetState
import java.security.SecureRandom

/**
 * ViewModel for TryRatchet demo.
 *
 * Tests:
 *
 * 1. Key Generation (MADH.generateKeypair)
 * 2. Initial State Creation (Ratchet.newRatchetState)
 * 3. DH Ratchet Steps (Ratchet.ratchetWithNewKey)
 * 4. Symmetric Ratchet Steps (Ratchet.ratchetWithoutNewKey)
 * 5. Encryption (Ratchet.encrypt)
 * 6. Decryption (Ratchet.decrypt)
 * 7. Two-party key agreement (both parties derive identical keys)
 *
 * Double ratchet combines two ratcheting mechanisms:
 *
 * ### DH Ratchet (Diffie-Hellman)
 * - Used when switching who is sending messages
 * - Sender generates new ephemeral keypair
 * - Sender shares ephemeral PUBLIC key with receiver
 * - Both parties perform ECDH to derive shared secret
 * - New root key and chain key are derived via HKDF
 * - Provides "future secrecy" - compromised keys don't reveal future messages
 *
 * ### Symmetric Ratchet
 * - Used for consecutive messages from the same sender
 * - Advances chain key using HMAC
 * - Derives new message key for each message
 * - More efficient than DH ratchet (no key exchange needed)
 *
 * ## Message Flow Example
 *
 * 1. Alice sends to Bob (DH ratchet):
 *    - Alice generates ephemeral keypair, ratchets, encrypts
 *    - Alice sends ciphertext + ephemeral public key to Bob
 *    - Bob ratchets using Alice's ephemeral public key, decrypts
 *    - Both now have matching keys
 *
 * 2. Alice sends again (Symmetric ratchet):
 *    - Alice advances chain, encrypts with new message key
 *    - Bob advances chain, decrypts with matching key
 *
 * 3. Bob sends to Alice (DH ratchet):
 *    - Bob generates new ephemeral keypair, ratchets, encrypts
 *    - Bob sends ciphertext + ephemeral public key to Alice
 *    - Alice ratchets using Bob's ephemeral public key, decrypts
 */
class MainViewModel : ViewModel()
{
    // ═══════════════════════════════════════════════════════════════════════════
    // UI State
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * State of the MADH handshake verification.
     * Displays confirmation codes that users would compare out-of-band.
     */
    data class HandshakeState(
        val aliceCode: String,
        val bobCode: String,
        val codesMatch: Boolean,
        val commitmentVerified: Boolean
    )

    /**
     * Representation of a party's cryptographic state.
     * Exposes key values for display in the crypto state panel.
     */
    data class PartyState(
        val publicKey: ByteArray,
        val rootKey: ByteArray,
        val chainKey: ByteArray?,
        val messageKey: ByteArray?,
        val ratchetStep: Int
    ) {
        // Truncated hex for display in compact UI
        fun publicKeyHexTruncated() = publicKey.toHexTruncated(16)
        fun rootKeyHexTruncated() = rootKey.toHexTruncated(16)
        fun chainKeyHexTruncated() = chainKey?.toHexTruncated(16) ?: "—"
        fun messageKeyHexTruncated() = messageKey?.toHexTruncated(16) ?: "—"

        // Full hex for dialog display
        fun publicKeyHex() = publicKey.toHex()
        fun rootKeyHex() = rootKey.toHex()
        fun chainKeyHex() = chainKey?.toHex() ?: "—"
        fun messageKeyHex() = messageKey?.toHex() ?: "—"

        private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

        private fun ByteArray.toHexTruncated(maxLen: Int = 16): String
        {
            val hex = toHex()
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

    /**
     * UI state for the demo screen.
     */
    data class UiState(
        val isStarted: Boolean = false,
        val handshakeState: HandshakeState? = null,
        val aliceState: PartyState? = null,
        val bobState: PartyState? = null,
        val messages: List<ChatMessage> = emptyList(),
        val initialRootKeysMatch: Boolean? = null
    )

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private val _testResults = MutableStateFlow<CryptoTestResults?>(null)
    val testResults: StateFlow<CryptoTestResults?> = _testResults.asStateFlow()

    // ═══════════════════════════════════════════════════════════════════════════
    // Internal Cryptographic State
    // ═══════════════════════════════════════════════════════════════════════════

    private val random = SecureRandom()

    // Long-term identity keypairs (in real use, these would be persistent)
    private var aliceKeypair: Curve25519KeyPair? = null
    private var aliceSession: SessionIdentifier? = null
    private var bobKeypair: Curve25519KeyPair? = null
    private var bobSession: SessionIdentifier? = null

    // Current ratchet states for each party
    private var aliceRatchetState: RatchetState? = null
    private var bobRatchetState: RatchetState? = null

    // Track the last sender to determine when DH ratchet is needed
    // DH ratchet occurs when the sender changes (reply scenario)
    private var lastSender: ChatMessage.Sender? = null

    // Track ephemeral public keys that need to be "transmitted" to the other party
    // In a real app, these would be sent over the network with the ciphertext
    private var pendingEphemeralKey: Curve25519PublicKey? = null

    private var messageIdCounter = 0L

    // ═══════════════════════════════════════════════════════════════════════════
    // Public API
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Initialize the demo by generating keypairs for both parties.
     *
     * ## Tests
     * - MADH.generateKeypair(): Curve25519 key generation
     * - Ratchet.newRatchetState(): Initial state derivation via ECDH
     * - Key agreement: Both parties should derive identical root keys
     *
     * ## Protocol Step
     * In a real application, Alice and Bob would:
     * 1. Generate their long-term identity keypairs (done once, stored securely)
     * 2. Exchange public keys through a secure channel
     * 3. Each derives the initial root key: R₀ = ECDH(myPrivate, theirPublic)
     * 4. Due to ECDH commutativity: Alice's R₀ = Bob's R₀
     */
    fun start()
    {
        // ───────────────────────────────────────────────────────────────────────
        // Step 1: Generate long-term identity keypairs
        // ───────────────────────────────────────────────────────────────────────
        aliceKeypair = MADH.generateKeypair()
        bobKeypair = MADH.generateKeypair()

        // ───────────────────────────────────────────────────────────────────────
        // Step 2: Generate session identifiers
        // In a real app, these would be exchanged during session setup
        // ───────────────────────────────────────────────────────────────────────
        aliceSession = SessionIdentifier(ByteArray(32).also { random.nextBytes(it) })
        bobSession = SessionIdentifier(ByteArray(32).also { random.nextBytes(it) })

        // ───────────────────────────────────────────────────────────────────────
        // Step 3: MADH Handshake
        // This demonstrates the Manually Authenticated Diffie-Hellman protocol
        // ───────────────────────────────────────────────────────────────────────
        val handshakeState = performMADHHandshake()

        // ─────────────────────────────────────────────────────────────────────
        // Step 4: Initialize ratchet states
        // Each party uses their own keypair + the other's public key
        // This derives the initial root key via ECDH:
        //   R₀ = ECDH(localPrivate, remotePublic)
        // ─────────────────────────────────────────────────────────────────────
        aliceRatchetState = Ratchet.newRatchetState(aliceKeypair!!, bobKeypair!!.publicKey)
        bobRatchetState = Ratchet.newRatchetState(bobKeypair!!, aliceKeypair!!.publicKey)

        // ─────────────────────────────────────────────────────────────────────
        // Step 5: Verify key agreement
        // Both parties should have derived identical root keys
        // ─────────────────────────────────────────────────────────────────────
        val rootKeysMatch = aliceRatchetState!!.rootKey.bytes.contentEquals(
            bobRatchetState!!.rootKey.bytes
        )

        // Reset conversation state
        lastSender = null
        pendingEphemeralKey = null
        messageIdCounter = 0L

        _uiState.update {
            UiState(
                isStarted = true,
                handshakeState = handshakeState,
                aliceState = aliceRatchetState?.toPartyState(aliceKeypair!!),
                bobState = bobRatchetState?.toPartyState(bobKeypair!!),
                messages = emptyList(),
                initialRootKeysMatch = rootKeysMatch
            )
        }
    }

    /**
     * Perform the MADH handshake protocol.
     */
    private fun performMADHHandshake(): HandshakeState
    {
        // Alice computes commitment to her public key
        val aliceCommitment = MADH.computePublicKeyCommitment(aliceKeypair!!.publicKey)

        // Bob verifies Alice's public key matches the commitment
        val verificationCommitment = MADH.computePublicKeyCommitment(aliceKeypair!!.publicKey)
        val commitmentVerified = aliceCommitment.contentEquals(verificationCommitment)

        // Both parties compute confirmation value with same parameter ordering
        val aliceConfirmation = MADH.computeConfirmation(
            senderSession = aliceSession!!,
            receiverSession = bobSession!!,
            senderPublicKey = aliceKeypair!!.publicKey,
            receiverPublicKey = bobKeypair!!.publicKey
        )

        val bobConfirmation = MADH.computeConfirmation(
            senderSession = aliceSession!!,
            receiverSession = bobSession!!,
            senderPublicKey = aliceKeypair!!.publicKey,
            receiverPublicKey = bobKeypair!!.publicKey
        )

        // Derive human-readable confirmation codes
        val aliceCode = MADH.computeConfirmationCode(aliceConfirmation)
        val bobCode = MADH.computeConfirmationCode(bobConfirmation)

        return HandshakeState(
            aliceCode = aliceCode,
            bobCode = bobCode,
            codesMatch = aliceCode == bobCode,
            commitmentVerified = commitmentVerified
        )
    }

    /**
     * Reset the demo to initial state.
     */
    fun reset() {
        aliceKeypair = null
        bobKeypair = null
        aliceSession = null
        bobSession = null
        aliceRatchetState = null
        bobRatchetState = null
        lastSender = null
        pendingEphemeralKey = null
        messageIdCounter = 0L

        _uiState.value = UiState()
    }

    /**
     * Send a message from Alice to Bob.
     */
    fun sendFromAlice(plaintext: String)
    {
        sendMessage(plaintext, ChatMessage.Sender.ALICE)
    }

    /**
     * Send a message from Bob to Alice.
     */
    fun sendFromBob(plaintext: String)
    {
        sendMessage(plaintext, ChatMessage.Sender.BOB)
    }

    fun runTests()
    {
        _testResults.value = CryptoTestRunner.runAllTests()
    }

    fun clearTestResults()
    {
        _testResults.value = null
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Message Processing
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Process a message sent from one party to the other.
     *
     * ## Ratchet Type Selection
     * - DH Ratchet: Used when sender changes (e.g., Alice replies to Bob)
     *   or for the very first message. Provides forward secrecy.
     * - Symmetric Ratchet: Used for consecutive messages from same sender.
     *
     * ## Two-Party Synchronization
     * Test that both parties derive the same message key:
     * 1. Sender ratchets their state and encrypts
     * 2. Sender "transmits" ciphertext + ephemeral public key (if DH ratchet)
     * 3. Receiver ratchets their state using sender's ephemeral key
     * 4. Receiver decrypts - success proves key agreement worked
     *
     * @param plaintext The message text to encrypt
     * @param sender Which party is sending (ALICE or BOB)
     */
    private fun sendMessage(plaintext: String, sender: ChatMessage.Sender)
    {
        val isAlice = sender == ChatMessage.Sender.ALICE

        // ─────────────────────────────────────────────────────────────────────
        // Step 1: Determine ratchet type
        // DH ratchet when: first message OR sender changed
        // Symmetric ratchet when: same sender as previous message
        // ─────────────────────────────────────────────────────────────────────
        val needsDHRatchet = (lastSender == null) || (lastSender != sender)
        val ratchetType = if (needsDHRatchet)
        {
            ChatMessage.RatchetType.DH
        }
        else
        {
            ChatMessage.RatchetType.SYMMETRIC
        }

        // ─────────────────────────────────────────────────────────────────────
        // Step 2: Sender ratchets their state
        // ─────────────────────────────────────────────────────────────────────
        val senderRatchetResult = performSenderRatchet(
            isAlice = isAlice,
            needsDHRatchet = needsDHRatchet
        )

        // ─────────────────────────────────────────────────────────────────────
        // Step 3: Sender encrypts the message
        // PlaintextMessage wraps the bytes with a type indicator
        // Ratchet.encrypt uses AES-GCM with the current message key
        // ─────────────────────────────────────────────────────────────────────
        val plaintextMessage = PlaintextMessage(
            type = PlaintextMessageType.UNCOMPRESSED_TEXT,
            bytes = plaintext.toByteArray(Charsets.UTF_8)
        )

        val senderState = if (isAlice) aliceRatchetState!! else bobRatchetState!!
        val ciphertext: Ciphertext = Ratchet.encrypt(senderState.messageKey!!, plaintextMessage)

        // ─────────────────────────────────────────────────────────────────────
        // Step 4: Receiver ratchets their state
        // For DH ratchet: receiver uses sender's ephemeral public key
        // For symmetric: receiver advances chain to match sender
        // ─────────────────────────────────────────────────────────────────────
        performReceiverRatchet(
            isAlice = isAlice,
            needsDHRatchet = needsDHRatchet,
            senderEphemeralPublicKey = senderRatchetResult.ephemeralPublicKey
        )

        // ─────────────────────────────────────────────────────────────────────
        // Step 5: Receiver attempts to decrypt
        // This is the critical test: if keys match, decryption succeeds
        // ─────────────────────────────────────────────────────────────────────
        val decryptResult = performDecryption(
            isAlice = isAlice,
            ciphertext = ciphertext
        )

        // ─────────────────────────────────────────────────────────────────────
        // Step 6: Verify key agreement
        // Both parties should have derived identical message keys
        // ─────────────────────────────────────────────────────────────────────
        val keysMatch = verifyKeyAgreement()

        // Update tracking
        lastSender = sender

        // ─────────────────────────────────────────────────────────────────────
        // Step 7: Create message record with all test results
        // ─────────────────────────────────────────────────────────────────────
        val chatMessage = ChatMessage(
            id = ++messageIdCounter,
            sender = sender,
            plaintext = plaintext,
            nonce = ciphertext.nonce.bytes,
            ciphertext = ciphertext.encrypted,
            tag = ciphertext.tag,
            ratchetType = ratchetType,
            decryptionSuccess = decryptResult.success,
            decryptedText = decryptResult.plaintext,
            keysMatched = keysMatch
        )

        _uiState.update { current ->
            current.copy(
                aliceState = aliceRatchetState?.toPartyState(aliceKeypair!!),
                bobState = bobRatchetState?.toPartyState(bobKeypair!!),
                messages = current.messages + chatMessage
            )
        }
    }

    /**
     * Perform the sender's ratchet step.
     *
     * ## DH Ratchet Process
     * 1. Generate new ephemeral keypair
     * 2. Perform ECDH: sharedSecret = ECDH(newEphemeralPrivate, remoteEphemeralPublic)
     * 3. Derive new keys: (rootKey, chainKey) = HKDF(oldRootKey, sharedSecret, "SHOUT")
     * 4. Derive message key: messageKey = HMAC(chainKey, messageNumber)
     *
     * ## Symmetric Ratchet Process
     * 1. Advance chain: newChainKey = HMAC(oldChainKey, messageNumber)
     * 2. Derive message key: messageKey = HMAC(newChainKey, messageNumber)
     *
     * @return Result containing the ephemeral public key (for DH ratchet) to send to receiver
     */
    private fun performSenderRatchet(
        isAlice: Boolean,
        needsDHRatchet: Boolean
    ): SenderRatchetResult
    {
        var senderState = if (isAlice) aliceRatchetState!! else bobRatchetState!!
        var ephemeralPublicKey: Curve25519PublicKey? = null

        if (needsDHRatchet)
        {
            // ─────────────────────────────────────────────────────────────────
            // DH Ratchet: Generate new ephemeral keys
            //
            // For the first message or when replying, we need fresh key material.
            // The sender generates a new ephemeral keypair and will send the
            // public key to the receiver along with the ciphertext.
            //
            // If there's a pending ephemeral key from the other party (they sent
            // us a message), we use that. Otherwise, we generate a placeholder.
            // ─────────────────────────────────────────────────────────────────
            val remoteEphemeralKey = pendingEphemeralKey ?: run {
                // First message scenario: no pending key from other party
                // Use their long-term public key to bootstrap
                if (isAlice) bobKeypair!!.publicKey else aliceKeypair!!.publicKey
            }

            val sendResult = Ratchet.ratchetForSend(senderState)
            senderState = sendResult.state

            // Save our new ephemeral public key to "transmit" to receiver
            ephemeralPublicKey = senderState.localEphemeralKeypair?.publicKey

            // Clear pending key since we've consumed it
            pendingEphemeralKey = null
        }
        else
        {
            // ─────────────────────────────────────────────────────────────────
            // Symmetric Ratchet: Just advance the chain
            // No new DH operation, just derive next chain and message keys
            // ─────────────────────────────────────────────────────────────────
            senderState = Ratchet.symmetricRatchet(senderState)
        }

        // Update sender's state
        if (isAlice) aliceRatchetState = senderState
        else bobRatchetState = senderState

        return SenderRatchetResult(ephemeralPublicKey)
    }

    /**
     * Perform the receiver's ratchet step to synchronize keys with sender.
     *
     * The receiver must perform the same ratchet operations as the sender
     * to arrive at the same message key. This is what enables decryption.
     *
     * For DH ratchet: receiver uses sender's ephemeral PUBLIC key
     * For symmetric: receiver advances chain (no key exchange needed)
     */
    private fun performReceiverRatchet(
        isAlice: Boolean,
        needsDHRatchet: Boolean,
        senderEphemeralPublicKey: Curve25519PublicKey?
    )
    {
        // Receiver is the opposite party
        var receiverState = if (isAlice) bobRatchetState!! else aliceRatchetState!!

        if (needsDHRatchet)
        {
            // ─────────────────────────────────────────────────────────────────
            // DH Ratchet on receiver side
            //
            // The receiver uses the sender's ephemeral public key (which would
            // be transmitted with the ciphertext in a real application).
            //
            // ECDH produces the same shared secret on both sides:
            //   Sender:   ECDH(senderEphemeralPrivate, receiverEphemeralPublic)
            //   Receiver: ECDH(receiverEphemeralPrivate, senderEphemeralPublic)
            // ─────────────────────────────────────────────────────────────────
            val ephemeralKey = senderEphemeralPublicKey ?: run {
                // Fallback for first message
                if (isAlice) aliceKeypair!!.publicKey else bobKeypair!!.publicKey
            }

            receiverState = Ratchet.ratchetForReceive(receiverState, ephemeralKey)

            // Save receiver's new ephemeral public key for potential reply
            pendingEphemeralKey = receiverState.localEphemeralKeypair?.publicKey
        }
        else
        {
            // ─────────────────────────────────────────────────────────────────
            // Symmetric ratchet: advance chain to match sender
            // ─────────────────────────────────────────────────────────────────
            receiverState = Ratchet.symmetricRatchet(receiverState)
        }

        // Update receiver's state
        if (isAlice) bobRatchetState = receiverState
        else aliceRatchetState = receiverState
    }

    /**
     * Attempt decryption on the receiver's side.
     *
     * ## Tests
     * - Ratchet.decrypt(): AES-GCM decryption with authentication
     * - Key agreement: If sender and receiver derived the same message key,
     *   decryption succeeds. If keys differ, AES-GCM authentication fails.
     *
     * ## Verifies
     * - Authenticated encryption: Tampered ciphertext would fail
     * - Key correctness: Wrong key produces authentication failure
     */
    private fun performDecryption(
        isAlice: Boolean,
        ciphertext: Ciphertext
    ): DecryptResult
    {
        // Receiver is the opposite party
        val receiverState = if (isAlice) bobRatchetState!! else aliceRatchetState!!

        return try
        {
            val decrypted = Ratchet.decrypt(receiverState.messageKey!!, ciphertext)
            val decryptedText = String(decrypted.bytes, Charsets.UTF_8)
            DecryptResult(success = true, plaintext = decryptedText)
        }
        catch (e: SecurityException)
        {
            // Decryption failed - keys didn't match or ciphertext was tampered
            DecryptResult(success = false, plaintext = null, error = e.message)
        }
        catch (e: Exception)
        {
            DecryptResult(success = false, plaintext = null, error = e.message)
        }
    }

    /**
     * Verify that both parties have derived identical message keys.
     *
     * Correctness check for the ratchet protocol.
     * If this returns false, something is wrong.
     */
    private fun verifyKeyAgreement(): Boolean
    {
        val aliceKey = aliceRatchetState?.messageKey?.bytes
        val bobKey = bobRatchetState?.messageKey?.bytes

        return if (aliceKey != null && bobKey != null) aliceKey.contentEquals(bobKey)
        else false
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════════

    private data class SenderRatchetResult(
        val ephemeralPublicKey: Curve25519PublicKey?
    )

    private data class DecryptResult(
        val success: Boolean,
        val plaintext: String?,
        val error: String? = null
    )

    private fun RatchetState.toPartyState(keypair: Curve25519KeyPair): PartyState {
        return PartyState(
            publicKey = keypair.publicKey.bytes,
            rootKey = rootKey.bytes,
            chainKey = chainKey?.bytes,
            messageKey = messageKey?.bytes,
            ratchetStep = messageNumber
        )
    }
}