package org.operatorfoundation.tryratchet

data class CryptoTestResults(
    val tests: List<TestResult>
) {
    val passCount: Int get() = tests.count { it.passed }
    val failCount: Int get() = tests.count { !it.passed }
    val allPassed: Boolean get() = failCount == 0

    data class TestResult(
        val category: Category,
        val name: String,
        val passed: Boolean,
        val details: String,
        val errorMessage: String? = null
    )

    enum class Category
    {
        MADH_KEY_GENERATION,
        MADH_HANDSHAKE,
        AES_ENCRYPTION,
        RATCHET_INIT,
        RATCHET_DH,
        RATCHET_SYMMETRIC,
        RATCHET_TWO_PARTY,
        END_TO_END
    }
}