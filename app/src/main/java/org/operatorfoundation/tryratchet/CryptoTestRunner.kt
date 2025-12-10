package org.operatorfoundation.tryratchet

import org.operatorfoundation.aes.AesCipher
import org.operatorfoundation.aes.AesGcmKey
import org.operatorfoundation.aes.Ciphertext
import org.operatorfoundation.aes.Nonce
import org.operatorfoundation.madh.Curve25519KeyPair
import org.operatorfoundation.madh.MADH
import org.operatorfoundation.madh.SessionIdentifier
import org.operatorfoundation.ratchet.PlaintextMessage
import org.operatorfoundation.ratchet.PlaintextMessageType
import org.operatorfoundation.ratchet.Ratchet
import org.operatorfoundation.ratchet.RatchetState
import java.security.SecureRandom
import org.operatorfoundation.tryratchet.CryptoTestResults.TestResult
import org.operatorfoundation.tryratchet.CryptoTestResults.Category

/**
 * Test runner for the cryptographic library suite.
 *
 * Exercises MADHAndroid, AESAndroid, and RatchetAndroid to verify correct functionality.
 *
 * ## Tests:
 *
 * ### MADH (Manually Authenticated Diffie-Hellman)
 * - Key generation
 * - Public key commitment (for commitment scheme)
 * - Confirmation computation (both parties should match)
 * - Confirmation code generation (human-readable verification)
 *
 * ### AES-GCM Encryption
 * - Key generation
 * - Encrypt/decrypt round-trip
 * - Wrong key rejection
 * - Tampered ciphertext rejection
 *
 * ### Ratchet Protocol
 * - Initial state creation
 * - Root key agreement (both parties derive same R₀)
 * - DH ratchet step (single party)
 * - Symmetric ratchet step
 * - Two-party key synchronization (KNOWN ISSUE)
 * - End-to-end message exchange
 */
object CryptoTestRunner
{

    fun runAllTests(): CryptoTestResults
    {
        val results = mutableListOf<TestResult>()

        // ═══════════════════════════════════════════════════════════════════
        // MADH: Key Generation Tests
        // ═══════════════════════════════════════════════════════════════════
        results.add(testMADHKeyGeneration())
        results.add(testMADHKeyUniqueness())

        // ═══════════════════════════════════════════════════════════════════
        // MADH: Handshake Tests
        // ═══════════════════════════════════════════════════════════════════
        results.add(testMADHPublicKeyCommitment())
        results.add(testMADHConfirmationMatch())
        results.add(testMADHConfirmationCodeFormat())
        results.add(testMADHFullHandshake())

        // ═══════════════════════════════════════════════════════════════════
        // AES: Encryption Tests
        // ═══════════════════════════════════════════════════════════════════
        results.add(testAESKeyGeneration())
        results.add(testAESEncryptDecryptRoundTrip())
        results.add(testAESWrongKeyRejection())
        results.add(testAESTamperedCiphertextRejection())
        results.add(testAESTamperedTagRejection())
        results.add(testAESTamperedNonceRejection())
        results.add(testAESEmptyPlaintext())
        results.add(testAESUniqueNonces())

        // ═══════════════════════════════════════════════════════════════════
        // Ratchet: Initialization Tests
        // ═══════════════════════════════════════════════════════════════════
        results.add(testRatchetInitialState())
        results.add(testRatchetInitialRootKeyAgreement())

        // ═══════════════════════════════════════════════════════════════════
        // Ratchet: Single-Party Operation Tests
        // ═══════════════════════════════════════════════════════════════════
        results.add(testRatchetDHStep())
        results.add(testRatchetSymmetricStep())
        results.add(testRatchetEncryptDecryptSameState())
        results.add(testRatchetKeyProgression())

        // ═══════════════════════════════════════════════════════════════════
        // Ratchet: Two-Party Synchronization Tests
        // These tests document the current library behavior
        // ═══════════════════════════════════════════════════════════════════
        results.add(testRatchetTwoPartyFirstMessage())
        results.add(testRatchetTwoPartyReply())
        results.add(testRatchetTwoPartyConversation())

        // ═══════════════════════════════════════════════════════════════════
        // End-to-End Tests
        // ═══════════════════════════════════════════════════════════════════
        results.add(testEndToEndWithSameState())

        return CryptoTestResults(results)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MADH: Key Generation Tests
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Test: MADH.generateKeypair() produces valid Curve25519 keys
     *
     * Verifies:
     * - Public key is 32 bytes
     * - Private key is 32 bytes
     * - Keys are non-zero
     */
    private fun testMADHKeyGeneration(): TestResult
    {
        return try {
            val keypair = MADH.generateKeypair()

            val publicKeyValid = keypair.publicKey.bytes.size == 32 &&
                    !keypair.publicKey.bytes.all { it == 0.toByte() }
            val privateKeyValid = keypair.privateKey.bytes.size == 32 &&
                    !keypair.privateKey.bytes.all { it == 0.toByte() }

            TestResult(
                category = Category.MADH_KEY_GENERATION,
                name = "Key Generation",
                passed = publicKeyValid && privateKeyValid,
                details = "Public key: ${keypair.publicKey.bytes.size} bytes, " +
                        "Private key: ${keypair.privateKey.bytes.size} bytes"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.MADH_KEY_GENERATION,
                name = "Key Generation",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Multiple keypairs are unique
     */
    private fun testMADHKeyUniqueness(): TestResult
    {
        return try
        {
            val keypair1 = MADH.generateKeypair()
            val keypair2 = MADH.generateKeypair()
            val keypair3 = MADH.generateKeypair()

            val allUnique = !keypair1.publicKey.bytes.contentEquals(keypair2.publicKey.bytes) &&
                    !keypair2.publicKey.bytes.contentEquals(keypair3.publicKey.bytes) &&
                    !keypair1.publicKey.bytes.contentEquals(keypair3.publicKey.bytes)

            TestResult(
                category = Category.MADH_KEY_GENERATION,
                name = "Key Uniqueness",
                passed = allUnique,
                details = "Generated 3 keypairs, all unique: $allUnique"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.MADH_KEY_GENERATION,
                name = "Key Uniqueness",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MADH: Handshake Tests
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Test: Public key commitment produces consistent SHA256 hash
     *
     * The commitment scheme allows Alice to commit to her public key
     * before seeing Bob's, preventing key manipulation attacks.
     */
    private fun testMADHPublicKeyCommitment(): TestResult
    {
        return try
        {
            val keypair = MADH.generateKeypair()

            val commitment1 = MADH.computePublicKeyCommitment(keypair.publicKey)
            val commitment2 = MADH.computePublicKeyCommitment(keypair.publicKey)

            val isConsistent = commitment1.contentEquals(commitment2)
            val isCorrectSize = commitment1.size == 32 // SHA256 output

            TestResult(
                category = Category.MADH_HANDSHAKE,
                name = "Public Key Commitment",
                passed = isConsistent && isCorrectSize,
                details = "Commitment size: ${commitment1.size} bytes, consistent: $isConsistent"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.MADH_HANDSHAKE,
                name = "Public Key Commitment",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Both parties compute the same confirmation value
     *
     * MA-DH: after exchanging public keys and session IDs,
     * both parties should derive the same confirmation value.
     */
    private fun testMADHConfirmationMatch(): TestResult
    {
        return try
        {
            val random = SecureRandom()

            // Alice and Bob generate keypairs
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            // Generate session identifiers
            val aliceSession = SessionIdentifier(ByteArray(32).also { random.nextBytes(it) })
            val bobSession = SessionIdentifier(ByteArray(32).also { random.nextBytes(it) })

            // Both compute confirmation with SAME parameter order
            // (sender=Alice, receiver=Bob for this exchange)
            val aliceConfirmation = MADH.computeConfirmation(
                senderSession = aliceSession,
                receiverSession = bobSession,
                senderPublicKey = aliceKeypair.publicKey,
                receiverPublicKey = bobKeypair.publicKey
            )

            val bobConfirmation = MADH.computeConfirmation(
                senderSession = aliceSession,
                receiverSession = bobSession,
                senderPublicKey = aliceKeypair.publicKey,
                receiverPublicKey = bobKeypair.publicKey
            )

            val confirmationsMatch = aliceConfirmation.bytes.contentEquals(bobConfirmation.bytes)

            TestResult(
                category = Category.MADH_HANDSHAKE,
                name = "Confirmation Match",
                passed = confirmationsMatch,
                details = "Alice and Bob confirmations match: $confirmationsMatch"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.MADH_HANDSHAKE,
                name = "Confirmation Match",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Confirmation code is a valid decimal string
     */
    private fun testMADHConfirmationCodeFormat(): TestResult
    {
        return try
        {
            val random = SecureRandom()
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()
            val aliceSession = SessionIdentifier(ByteArray(32).also { random.nextBytes(it) })
            val bobSession = SessionIdentifier(ByteArray(32).also { random.nextBytes(it) })

            val confirmation = MADH.computeConfirmation(
                aliceSession, bobSession,
                aliceKeypair.publicKey, bobKeypair.publicKey
            )
            val code = MADH.computeConfirmationCode(confirmation)

            // Code should be a decimal number (0 to 16777215 for 24 bits)
            val isNumeric = code.all { it.isDigit() }
            val value = code.toLongOrNull()
            val inRange = value != null && value in 0..16777215

            TestResult(
                category = Category.MADH_HANDSHAKE,
                name = "Confirmation Code Format",
                passed = isNumeric && inRange,
                details = "Code: $code, numeric: $isNumeric, in range: $inRange"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.MADH_HANDSHAKE,
                name = "Confirmation Code Format",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Full MA-DH handshake flow
     *
     * Simulates the complete handshake:
     * 1. Alice generates keypair and commitment
     * 2. Alice sends commitment to Bob
     * 3. Bob generates keypair and sends public key to Alice
     * 4. Alice sends her public key to Bob
     * 5. Bob verifies Alice's key matches commitment
     * 6. Both compute confirmation codes and compare (out-of-band)
     */
    private fun testMADHFullHandshake(): TestResult
    {
        return try
        {
            val random = SecureRandom()

            // Step 1: Alice generates keypair
            val aliceKeypair = MADH.generateKeypair()
            val aliceSession = SessionIdentifier(ByteArray(32).also { random.nextBytes(it) })

            // Step 2: Alice computes commitment
            val aliceCommitment = MADH.computePublicKeyCommitment(aliceKeypair.publicKey)

            // Step 3: Bob generates keypair (after receiving commitment)
            val bobKeypair = MADH.generateKeypair()
            val bobSession = SessionIdentifier(ByteArray(32).also { random.nextBytes(it) })

            // Step 4: Bob sends public key to Alice
            // Step 5: Alice sends public key to Bob

            // Step 6: Bob verifies Alice's public key matches commitment
            val verificationCommitment = MADH.computePublicKeyCommitment(aliceKeypair.publicKey)
            val commitmentVerified = aliceCommitment.contentEquals(verificationCommitment)

            // Step 7: Both compute confirmation codes
            val aliceConfirmation = MADH.computeConfirmation(
                aliceSession, bobSession,
                aliceKeypair.publicKey, bobKeypair.publicKey
            )

            val bobConfirmation = MADH.computeConfirmation(
                aliceSession, bobSession,
                aliceKeypair.publicKey, bobKeypair.publicKey
            )

            val aliceCode = MADH.computeConfirmationCode(aliceConfirmation)
            val bobCode = MADH.computeConfirmationCode(bobConfirmation)

            val codesMatch = aliceCode == bobCode

            TestResult(
                category = Category.MADH_HANDSHAKE,
                name = "Full Handshake Flow",
                passed = commitmentVerified && codesMatch,
                details = "Commitment verified: $commitmentVerified, " +
                        "Codes match: $codesMatch (Alice: $aliceCode, Bob: $bobCode)"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.MADH_HANDSHAKE,
                name = "Full Handshake Flow",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // AES: Encryption Tests
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Test: AES key generation produces valid 256-bit keys
     */
    private fun testAESKeyGeneration(): TestResult
    {
        return try
        {
            val key = AesGcmKey.generate()

            val validSize = key.bytes.size == 32
            val nonZero = !key.bytes.all { it == 0.toByte() }

            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Key Generation",
                passed = validSize && nonZero,
                details = "Key size: ${key.bytes.size} bytes (expected 32)"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Key Generation",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Encrypt then decrypt recovers original plaintext
     */
    private fun testAESEncryptDecryptRoundTrip(): TestResult
    {
        return try {
            val cipher = AesCipher()
            val key = AesGcmKey.generate()
            val plaintext = "Hello, World! This is a test message.".toByteArray()

            val ciphertext = cipher.encrypt(key, plaintext)
            val decrypted = cipher.decrypt(key, ciphertext)

            val matches = plaintext.contentEquals(decrypted)

            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Encrypt/Decrypt Round-Trip",
                passed = matches,
                details = "Original: ${plaintext.size} bytes, Decrypted: ${decrypted.size} bytes, Match: $matches"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Encrypt/Decrypt Round-Trip",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Decryption with wrong key throws SecurityException
     */
    private fun testAESWrongKeyRejection(): TestResult
    {
        return try
        {
            val cipher = AesCipher()
            val correctKey = AesGcmKey.generate()
            val wrongKey = AesGcmKey.generate()
            val plaintext = "Secret message".toByteArray()

            val ciphertext = cipher.encrypt(correctKey, plaintext)

            var threwException = false
            try {
                cipher.decrypt(wrongKey, ciphertext)
            } catch (e: SecurityException) {
                threwException = true
            }

            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Wrong Key Rejection",
                passed = threwException,
                details = "SecurityException thrown: $threwException"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Wrong Key Rejection",
                passed = false,
                details = "Unexpected exception",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Tampered ciphertext is rejected
     */
    private fun testAESTamperedCiphertextRejection(): TestResult
    {
        return try
        {
            val cipher = AesCipher()
            val key = AesGcmKey.generate()
            val plaintext = "Secret message".toByteArray()

            val ciphertext = cipher.encrypt(key, plaintext)

            // Tamper with encrypted bytes
            val tampered = ciphertext.encrypted.clone()
            tampered[0] = (tampered[0] + 1).toByte()
            val tamperedCiphertext = Ciphertext(ciphertext.nonce, tampered, ciphertext.tag)

            var threwException = false
            try {
                cipher.decrypt(key, tamperedCiphertext)
            } catch (e: SecurityException) {
                threwException = true
            }

            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Tampered Ciphertext Rejection",
                passed = threwException,
                details = "SecurityException thrown: $threwException"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Tampered Ciphertext Rejection",
                passed = false,
                details = "Unexpected exception",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Tampered authentication tag is rejected
     */
    private fun testAESTamperedTagRejection(): TestResult
    {
        return try
        {
            val cipher = AesCipher()
            val key = AesGcmKey.generate()
            val plaintext = "Secret message".toByteArray()

            val ciphertext = cipher.encrypt(key, plaintext)

            // Tamper with tag
            val tamperedTag = ciphertext.tag.clone()
            tamperedTag[0] = (tamperedTag[0] + 1).toByte()
            val tamperedCiphertext = Ciphertext(ciphertext.nonce, ciphertext.encrypted, tamperedTag)

            var threwException = false
            try
            {
                cipher.decrypt(key, tamperedCiphertext)
            }
            catch (e: SecurityException)
            {
                threwException = true
            }

            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Tampered Tag Rejection",
                passed = threwException,
                details = "SecurityException thrown: $threwException"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Tampered Tag Rejection",
                passed = false,
                details = "Unexpected exception",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Tampered nonce is rejected
     */
    private fun testAESTamperedNonceRejection(): TestResult
    {
        return try
        {
            val cipher = AesCipher()
            val key = AesGcmKey.generate()
            val plaintext = "Secret message".toByteArray()

            val ciphertext = cipher.encrypt(key, plaintext)

            // Tamper with nonce
            val tamperedNonceBytes = ciphertext.nonce.bytes.clone()
            tamperedNonceBytes[0] = (tamperedNonceBytes[0] + 1).toByte()
            val tamperedCiphertext = Ciphertext(
                Nonce(tamperedNonceBytes),
                ciphertext.encrypted,
                ciphertext.tag
            )

            var threwException = false
            try {
                cipher.decrypt(key, tamperedCiphertext)
            } catch (e: SecurityException) {
                threwException = true
            }

            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Tampered Nonce Rejection",
                passed = threwException,
                details = "SecurityException thrown: $threwException"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Tampered Nonce Rejection",
                passed = false,
                details = "Unexpected exception",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Empty plaintext can be encrypted and decrypted
     */
    private fun testAESEmptyPlaintext(): TestResult
    {
        return try {
            val cipher = AesCipher()
            val key = AesGcmKey.generate()
            val plaintext = ByteArray(0)

            val ciphertext = cipher.encrypt(key, plaintext)
            val decrypted = cipher.decrypt(key, ciphertext)

            val matches = plaintext.contentEquals(decrypted)

            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Empty Plaintext",
                passed = matches && decrypted.isEmpty(),
                details = "Empty plaintext encrypted and decrypted successfully"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Empty Plaintext",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Each encryption produces a unique nonce
     */
    private fun testAESUniqueNonces(): TestResult
    {
        return try
        {
            val cipher = AesCipher()
            val key = AesGcmKey.generate()
            val plaintext = "Test".toByteArray()

            val ciphertext1 = cipher.encrypt(key, plaintext)
            val ciphertext2 = cipher.encrypt(key, plaintext)
            val ciphertext3 = cipher.encrypt(key, plaintext)

            val allUnique = !ciphertext1.nonce.bytes.contentEquals(ciphertext2.nonce.bytes) &&
                    !ciphertext2.nonce.bytes.contentEquals(ciphertext3.nonce.bytes) &&
                    !ciphertext1.nonce.bytes.contentEquals(ciphertext3.nonce.bytes)

            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Unique Nonces",
                passed = allUnique,
                details = "All 3 nonces unique: $allUnique"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.AES_ENCRYPTION,
                name = "Unique Nonces",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Ratchet: Initialization Tests
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Test: newRatchetState creates valid initial state
     */
    private fun testRatchetInitialState(): TestResult
    {
        return try
        {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            val state = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

            val hasRootKey = state.rootKey.bytes.size == 32
            val hasLongtermKeys = state.localLongtermKeypair == aliceKeypair
            val messageNumberZero = state.messageNumber == 0
            val noEphemeralYet = state.localEphemeralKeypair == null

            TestResult(
                category = Category.RATCHET_INIT,
                name = "Initial State Creation",
                passed = hasRootKey && hasLongtermKeys && messageNumberZero && noEphemeralYet,
                details = "Root key: ${state.rootKey.bytes.size} bytes, " +
                        "Message #: ${state.messageNumber}, " +
                        "Ephemeral keys: ${state.localEphemeralKeypair != null}"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.RATCHET_INIT,
                name = "Initial State Creation",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Both parties derive the same initial root key (R₀)
     *
     * This tests the fundamental ECDH property:
     * ECDH(alice_priv, bob_pub) = ECDH(bob_priv, alice_pub)
     */
    private fun testRatchetInitialRootKeyAgreement(): TestResult
    {
        return try
        {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            val aliceState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val bobState = Ratchet.newRatchetState(bobKeypair, aliceKeypair.publicKey)

            val rootKeysMatch = aliceState.rootKey.bytes.contentEquals(bobState.rootKey.bytes)

            TestResult(
                category = Category.RATCHET_INIT,
                name = "Initial Root Key Agreement",
                passed = rootKeysMatch,
                details = "Alice R₀ = Bob R₀: $rootKeysMatch"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.RATCHET_INIT,
                name = "Initial Root Key Agreement",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Ratchet: Single-Party Operation Tests
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Test: DH ratchet step advances all keys
     */
    private fun testRatchetDHStep(): TestResult
    {
        return try
        {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val newRemoteEphemeral = MADH.generateKeypair().publicKey

            val newState = Ratchet.ratchetWithNewKey(initialState, newRemoteEphemeral)

            val rootKeyChanged = !initialState.rootKey.bytes.contentEquals(newState.rootKey.bytes)
            val hasChainKey = newState.chainKey != null
            val hasMessageKey = newState.messageKey != null
            val hasEphemeralKeypair = newState.localEphemeralKeypair != null
            val messageNumberIncremented = newState.messageNumber == 1

            TestResult(
                category = Category.RATCHET_DH,
                name = "DH Ratchet Step",
                passed = rootKeyChanged && hasChainKey && hasMessageKey &&
                        hasEphemeralKeypair && messageNumberIncremented,
                details = "Root changed: $rootKeyChanged, Chain key: $hasChainKey, " +
                        "Message key: $hasMessageKey, Ephemeral: $hasEphemeralKeypair, " +
                        "Message #: ${newState.messageNumber}"
            )
        }
        catch (e: Exception)
        {
            TestResult(
                category = Category.RATCHET_DH,
                name = "DH Ratchet Step",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Symmetric ratchet advances chain and message keys
     */
    private fun testRatchetSymmetricStep(): TestResult {
        return try {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val remoteEphemeral = MADH.generateKeypair().publicKey

            // First do DH ratchet to get chain key
            val state1 = Ratchet.ratchetWithNewKey(initialState, remoteEphemeral)

            // Then do symmetric ratchet
            val state2 = Ratchet.ratchetWithoutNewKey(state1)

            val rootKeySame = state1.rootKey.bytes.contentEquals(state2.rootKey.bytes)
            val chainKeyChanged = !state1.chainKey!!.bytes.contentEquals(state2.chainKey!!.bytes)
            val messageKeyChanged = !state1.messageKey!!.bytes.contentEquals(state2.messageKey!!.bytes)
            val messageNumberIncremented = state2.messageNumber == 2

            TestResult(
                category = Category.RATCHET_SYMMETRIC,
                name = "Symmetric Ratchet Step",
                passed = rootKeySame && chainKeyChanged && messageKeyChanged && messageNumberIncremented,
                details = "Root same: $rootKeySame, Chain changed: $chainKeyChanged, " +
                        "Message key changed: $messageKeyChanged, Message #: ${state2.messageNumber}"
            )
        } catch (e: Exception) {
            TestResult(
                category = Category.RATCHET_SYMMETRIC,
                name = "Symmetric Ratchet Step",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Encrypt and decrypt with SAME state (single party)
     *
     * This is how the library's own tests work - using the same
     * message key for both encrypt and decrypt.
     */
    private fun testRatchetEncryptDecryptSameState(): TestResult {
        return try {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val remoteEphemeral = MADH.generateKeypair().publicKey
            val state = Ratchet.ratchetWithNewKey(initialState, remoteEphemeral)

            val plaintext = PlaintextMessage(
                PlaintextMessageType.UNCOMPRESSED_TEXT,
                "Hello, World!".toByteArray()
            )

            val ciphertext = Ratchet.encrypt(state.messageKey!!, plaintext)
            val decrypted = Ratchet.decrypt(state.messageKey!!, ciphertext)

            val textMatches = plaintext.bytes.contentEquals(decrypted.bytes)
            val typeMatches = plaintext.type == decrypted.type

            TestResult(
                category = Category.RATCHET_DH,
                name = "Encrypt/Decrypt Same State",
                passed = textMatches && typeMatches,
                details = "Text matches: $textMatches, Type matches: $typeMatches"
            )
        } catch (e: Exception) {
            TestResult(
                category = Category.RATCHET_DH,
                name = "Encrypt/Decrypt Same State",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Each message gets a unique key
     */
    private fun testRatchetKeyProgression(): TestResult {
        return try {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            val initialState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            val remoteEphemeral = MADH.generateKeypair().publicKey

            val state1 = Ratchet.ratchetWithNewKey(initialState, remoteEphemeral)
            val state2 = Ratchet.ratchetWithoutNewKey(state1)
            val state3 = Ratchet.ratchetWithoutNewKey(state2)

            val key1 = state1.messageKey!!.bytes
            val key2 = state2.messageKey!!.bytes
            val key3 = state3.messageKey!!.bytes

            val allUnique = !key1.contentEquals(key2) &&
                    !key2.contentEquals(key3) &&
                    !key1.contentEquals(key3)

            TestResult(
                category = Category.RATCHET_SYMMETRIC,
                name = "Key Progression",
                passed = allUnique,
                details = "All 3 message keys unique: $allUnique"
            )
        } catch (e: Exception) {
            TestResult(
                category = Category.RATCHET_SYMMETRIC,
                name = "Key Progression",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Ratchet: Two-Party Synchronization Tests
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Test: Two-party first message exchange
     *
     * This tests whether Alice and Bob can derive the same message key
     * when Alice sends the first message to Bob.
     *
     * EXPECTED TO FAIL with current library implementation.
     *
     * Protocol:
     * 1. Alice ratchets (generates new ephemeral, uses Bob's longterm pub)
     * 2. Alice encrypts and "sends" ciphertext + her ephemeral pub
     * 3. Bob ratchets using Alice's ephemeral pub
     * 4. Bob should derive same key and decrypt successfully
     *
     * Current issue: Bob's ratchetWithNewKey generates a NEW local
     * ephemeral instead of using his current/longterm key, resulting
     * in a different shared secret.
     */
    private fun testRatchetTwoPartyFirstMessage(): TestResult {
        return try {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            // Initialize both parties
            var aliceState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            var bobState = Ratchet.newRatchetState(bobKeypair, aliceKeypair.publicKey)

            // Verify initial root keys match
            val initialRootMatch = aliceState.rootKey.bytes.contentEquals(bobState.rootKey.bytes)

            // Alice sends first message (DH ratchet)
            // She uses Bob's longterm public key since no ephemeral yet
            aliceState = Ratchet.ratchetWithNewKey(aliceState, bobKeypair.publicKey)
            val aliceEphemeralPub = aliceState.localEphemeralKeypair!!.publicKey

            val plaintext = PlaintextMessage(
                PlaintextMessageType.UNCOMPRESSED_TEXT,
                "Hello Bob!".toByteArray()
            )
            val ciphertext = Ratchet.encrypt(aliceState.messageKey!!, plaintext)

            // Bob receives and ratchets using Alice's ephemeral
            // BUG: This generates a new keypair for Bob instead of using existing
            bobState = Ratchet.ratchetWithNewKey(bobState, aliceEphemeralPub)

            // Check if keys match
            val keysMatch = aliceState.messageKey!!.bytes.contentEquals(bobState.messageKey!!.bytes)

            // Try to decrypt
            var decryptSuccess = false
            var decryptedText = ""
            try {
                val decrypted = Ratchet.decrypt(bobState.messageKey!!, ciphertext)
                decryptSuccess = true
                decryptedText = String(decrypted.bytes, Charsets.UTF_8)
            } catch (e: Exception) {
                // Expected to fail
            }

            TestResult(
                category = Category.RATCHET_TWO_PARTY,
                name = "Two-Party First Message",
                passed = keysMatch && decryptSuccess,
                details = "Initial R₀ match: $initialRootMatch, " +
                        "Message keys match: $keysMatch, " +
                        "Decrypt success: $decryptSuccess" +
                        if (decryptSuccess) ", Text: \"$decryptedText\"" else ""
            )
        } catch (e: Exception) {
            TestResult(
                category = Category.RATCHET_TWO_PARTY,
                name = "Two-Party First Message",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Two-party reply scenario
     *
     * After Alice sends to Bob, Bob sends a reply.
     *
     * EXPECTED TO FAIL with current library implementation.
     */
    private fun testRatchetTwoPartyReply(): TestResult {
        return try {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            var aliceState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            var bobState = Ratchet.newRatchetState(bobKeypair, aliceKeypair.publicKey)

            // Alice sends first message
            aliceState = Ratchet.ratchetWithNewKey(aliceState, bobKeypair.publicKey)
            val aliceEph1 = aliceState.localEphemeralKeypair!!.publicKey

            // Bob receives (ratchets)
            bobState = Ratchet.ratchetWithNewKey(bobState, aliceEph1)
            val bobEph1 = bobState.localEphemeralKeypair!!.publicKey

            // Bob sends reply
            bobState = Ratchet.ratchetWithNewKey(bobState, aliceEph1)
            val bobEph2 = bobState.localEphemeralKeypair!!.publicKey

            val plaintext = PlaintextMessage(
                PlaintextMessageType.UNCOMPRESSED_TEXT,
                "Hello Alice!".toByteArray()
            )
            val ciphertext = Ratchet.encrypt(bobState.messageKey!!, plaintext)

            // Alice receives Bob's reply
            aliceState = Ratchet.ratchetWithNewKey(aliceState, bobEph2)

            val keysMatch = aliceState.messageKey!!.bytes.contentEquals(bobState.messageKey!!.bytes)

            var decryptSuccess = false
            try {
                Ratchet.decrypt(aliceState.messageKey!!, ciphertext)
                decryptSuccess = true
            } catch (e: Exception) {
                // Expected to fail
            }

            TestResult(
                category = Category.RATCHET_TWO_PARTY,
                name = "Two-Party Reply",
                passed = keysMatch && decryptSuccess,
                details = "Keys match: $keysMatch, Decrypt success: $decryptSuccess"
            )
        } catch (e: Exception) {
            TestResult(
                category = Category.RATCHET_TWO_PARTY,
                name = "Two-Party Reply",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    /**
     * Test: Full two-party conversation
     *
     * Alice → Bob → Alice → Bob
     *
     * EXPECTED TO FAIL with current library implementation.
     */
    private fun testRatchetTwoPartyConversation(): TestResult {
        return try {
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            var aliceState = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)
            var bobState = Ratchet.newRatchetState(bobKeypair, aliceKeypair.publicKey)

            var successCount = 0
            val messages = listOf(
                Pair("alice", "Message 1: Alice to Bob"),
                Pair("bob", "Message 2: Bob to Alice"),
                Pair("alice", "Message 3: Alice to Bob again"),
                Pair("bob", "Message 4: Bob to Alice again")
            )

            for ((sender, text) in messages) {
                val plaintext = PlaintextMessage(
                    PlaintextMessageType.UNCOMPRESSED_TEXT,
                    text.toByteArray()
                )

                if (sender == "alice") {
                    // Alice sends
                    val remoteKey = bobState.localEphemeralKeypair?.publicKey
                        ?: bobKeypair.publicKey
                    aliceState = Ratchet.ratchetWithNewKey(aliceState, remoteKey)
                    val aliceEph = aliceState.localEphemeralKeypair!!.publicKey

                    val ciphertext = Ratchet.encrypt(aliceState.messageKey!!, plaintext)

                    // Bob receives
                    bobState = Ratchet.ratchetWithNewKey(bobState, aliceEph)

                    try {
                        Ratchet.decrypt(bobState.messageKey!!, ciphertext)
                        successCount++
                    } catch (e: Exception) {
                        // Failed
                    }
                } else {
                    // Bob sends
                    val remoteKey = aliceState.localEphemeralKeypair?.publicKey
                        ?: aliceKeypair.publicKey
                    bobState = Ratchet.ratchetWithNewKey(bobState, remoteKey)
                    val bobEph = bobState.localEphemeralKeypair!!.publicKey

                    val ciphertext = Ratchet.encrypt(bobState.messageKey!!, plaintext)

                    // Alice receives
                    aliceState = Ratchet.ratchetWithNewKey(aliceState, bobEph)

                    try {
                        Ratchet.decrypt(aliceState.messageKey!!, ciphertext)
                        successCount++
                    } catch (e: Exception) {
                        // Failed
                    }
                }
            }

            TestResult(
                category = Category.RATCHET_TWO_PARTY,
                name = "Two-Party Conversation",
                passed = successCount == messages.size,
                details = "Successful decryptions: $successCount/${messages.size}"
            )
        } catch (e: Exception) {
            TestResult(
                category = Category.RATCHET_TWO_PARTY,
                name = "Two-Party Conversation",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // End-to-End Tests
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Test: Complete flow with same-state decrypt (workaround)
     *
     * This demonstrates that the individual components work correctly,
     * even if two-party synchronization doesn't.
     */
    private fun testEndToEndWithSameState(): TestResult {
        return try {
            // Generate keys
            val aliceKeypair = MADH.generateKeypair()
            val bobKeypair = MADH.generateKeypair()

            // Initialize ratchet
            var state = Ratchet.newRatchetState(aliceKeypair, bobKeypair.publicKey)

            // DH ratchet
            state = Ratchet.ratchetWithNewKey(state, bobKeypair.publicKey)

            // Send multiple messages with symmetric ratchet
            val messages = listOf("First message", "Second message", "Third message")
            var allSuccess = true

            for (text in messages) {
                val plaintext = PlaintextMessage(
                    PlaintextMessageType.UNCOMPRESSED_TEXT,
                    text.toByteArray()
                )

                val ciphertext = Ratchet.encrypt(state.messageKey!!, plaintext)
                val decrypted = Ratchet.decrypt(state.messageKey!!, ciphertext)

                if (!plaintext.bytes.contentEquals(decrypted.bytes)) {
                    allSuccess = false
                    break
                }

                // Advance ratchet for next message
                state = Ratchet.ratchetWithoutNewKey(state)
            }

            TestResult(
                category = Category.END_TO_END,
                name = "End-to-End Same State",
                passed = allSuccess,
                details = "All ${messages.size} messages encrypted/decrypted successfully"
            )
        } catch (e: Exception) {
            TestResult(
                category = Category.END_TO_END,
                name = "End-to-End Same State",
                passed = false,
                details = "Exception thrown",
                errorMessage = e.message
            )
        }
    }
}