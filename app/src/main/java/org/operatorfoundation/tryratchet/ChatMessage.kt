package org.operatorfoundation.tryratchet

/**
 * Represents a chat message in the demo, including the plaintext,
 * crypto details, and metadata about the ratchet operation used.
 */
data class ChatMessage(
    val id: Long,
    val sender: Sender,
    val plaintext: String,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
    val ratchetType: RatchetType
) {
    enum class Sender { ALICE, BOB }
    enum class RatchetType { DH, SYMMETRIC }

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