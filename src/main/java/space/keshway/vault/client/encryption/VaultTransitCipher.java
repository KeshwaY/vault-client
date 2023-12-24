package space.keshway.vault.client.encryption;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
final class VaultTransitCipher {

  private static final int ALGORITHM_NONCE_LENGTH = 12;
  private static final int ALGORITHM_SPEC_TLEN = 16 * 8;

  private static final int STARTING_POS = 0;

  private static final String TAG_VAULT = "vault:v%s:%s";
  private static final int TAG_BASE_LENGTH = 8;

  private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
  private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

  private final String keyVersion;
  private final SecretKeySpec keySpec;
  private final Cipher cipher;

  private static byte[] createNonceRandom() {
    byte[] nonceRandom = createNonceArray();
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(nonceRandom);
    return nonceRandom;
  }

  private static byte[] createNonceArray() {
    return new byte[ALGORITHM_NONCE_LENGTH];
  }

  private static GCMParameterSpec createParameterSpec(byte[] nonceRandom) {
    return new GCMParameterSpec(ALGORITHM_SPEC_TLEN, nonceRandom);
  }

  List<String> encrypt(List<String> data) {
    return data.stream()
        .map(this::encrypt)
        .map(BASE64_ENCODER::encodeToString)
        .map(this::appendTag)
        .toList();
  }

  private byte[] encrypt(String data) {
    try {
      byte[] nonceRandom = createNonceRandom();
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, createParameterSpec(nonceRandom));
      byte[] ciphertext = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
      byte[] ciphertextWithNonce = new byte[nonceRandom.length + ciphertext.length];
      System.arraycopy(nonceRandom, STARTING_POS, ciphertextWithNonce, 0, ALGORITHM_NONCE_LENGTH);
      System.arraycopy(
          ciphertext, STARTING_POS, ciphertextWithNonce, ALGORITHM_NONCE_LENGTH, ciphertext.length);
      return ciphertextWithNonce;
    } catch (IllegalBlockSizeException
        | BadPaddingException
        | InvalidAlgorithmParameterException
        | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  List<String> decrypt(List<String> data) {
    return data.stream().map(this::deleteTag).map(this::decrypt).map(String::new).toList();
  }

  private byte[] decrypt(String data) {
    try {
      byte[] decode = BASE64_DECODER.decode(data);
      byte[] ciphertextWithoutNonce = new byte[decode.length - ALGORITHM_NONCE_LENGTH];
      byte[] nonce = createNonceArray();
      System.arraycopy(
          decode,
          ALGORITHM_NONCE_LENGTH,
          ciphertextWithoutNonce,
          STARTING_POS,
          ciphertextWithoutNonce.length);
      System.arraycopy(decode, STARTING_POS, nonce, STARTING_POS, nonce.length);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, createParameterSpec(nonce));
      return cipher.doFinal(ciphertextWithoutNonce);
    } catch (IllegalBlockSizeException
        | BadPaddingException
        | InvalidKeyException
        | InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  private String appendTag(String data) {
    return String.format(TAG_VAULT, keyVersion, data);
  }

  private String deleteTag(String data) {
    return data.substring(TAG_BASE_LENGTH + keyVersion.length());
  }
}
