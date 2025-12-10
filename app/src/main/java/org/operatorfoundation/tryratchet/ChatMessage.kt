package org.operatorfoundation.tryratchet

/**
 * - decryptionSuccess: Did the receiver successfully decrypt?
 * - decryptedText: What text did decryption produce?
 * - keysMatched: Did both parties derive the same message key?
 */
data class ChatMessage(
    val id: Long,
    val sender: Sender,
    val plaintext: String,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
    val ratchetType: RatchetType,
    // Test results
    val decryptionSuccess: Boolean,
    val decryptedText: String?,
    val keysMatched: Boolean
) {
    enum class Sender { ALICE, BOB }
    enum class RatchetType { DH, SYMMETRIC }

    /**
     * Overall test passed: decryption worked and output matches input.
     */
    fun testPassed(): Boolean
    {
        return decryptionSuccess &&
                keysMatched &&
                decryptedText == plaintext
    }

    /**
     * Format a ByteArray as a hex string.
     */
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    fun nonceHex(): String = nonce.toHex()
    fun ciphertextHex(): String = ciphertext.toHex()
    fun tagHex(): String = tag.toHex()

    /**
     * Returns a truncated hex string for display (first N chars + "...").
     */
    fun ciphertextHexTruncated(maxLen: Int = 24): String
    {
        val full = ciphertextHex()
        return if (full.length > maxLen) "${full.take(maxLen)}..." else full
    }

    // ByteArray requires custom equals/hashCode
    override fun equals(other: Any?): Boolean
    {
        if (this === other) return true
        if (other !is ChatMessage) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}