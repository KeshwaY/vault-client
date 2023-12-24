package space.keshway.vault.client.encryption;

import static org.springframework.test.util.AssertionErrors.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertNotEquals;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class VaultTransitCipherTest {
  private static final String KEY = "kwaoTrZWmAb8UxOZONPcc47rarVTvVGy72buQorsyUI=";
  private static final String KEY_VERSION = "1";

  private static final int ALGORITHM_NONCE_LENGTH = 12;
  private static final String ALGORITHM = "AES";
  private static final String ALGORITHM_TRANSFORMATION = "AES/GCM/NoPadding";

  private static final String VALUE_TO_ENCRYPT = "test";
  private static final int FIRST_RESULT = 0;

  private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

  @Test
  public void encryptionTest_shouldEncryptAndDecrypt() throws Exception {
    byte[] keyBytes = BASE64_DECODER.decode(KEY);
    byte[] nonceRandom = new byte[ALGORITHM_NONCE_LENGTH];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(nonceRandom);
    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
    Cipher cipher = Cipher.getInstance(ALGORITHM_TRANSFORMATION);
    VaultTransitCipher vaultTransitCipher =
        new VaultTransitCipher(KEY_VERSION, secretKeySpec, cipher);

    List<String> encryptionResult = vaultTransitCipher.encrypt(List.of(VALUE_TO_ENCRYPT));
    List<String> decryptionResult = vaultTransitCipher.decrypt(encryptionResult);

    assertNotEquals(
        "Encrypted value should not be equal to the original one",
        VALUE_TO_ENCRYPT,
        encryptionResult.get(FIRST_RESULT));
    assertEquals(
        "Decrypted value should be equal to the original one",
        VALUE_TO_ENCRYPT,
        decryptionResult.get(FIRST_RESULT));
  }
}
