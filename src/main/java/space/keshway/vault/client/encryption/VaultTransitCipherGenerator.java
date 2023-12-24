package space.keshway.vault.client.encryption;

import com.google.common.base.Preconditions;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.TransitKeyType;
import org.springframework.vault.support.VaultTransitKey;
import space.keshway.vault.client.model.DataType;

// TODO: create object manager to fetch new keys
public final class VaultTransitCipherGenerator {

  private static final String ALGORITHM_ENCRYPTION = "AES";
  private static final String ALGORITHM_TRANSFORMATION = "AES/GCM/NoPadding";

  private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

  private final VaultOperations vaultOperations;

  VaultTransitCipherGenerator(VaultOperations vaultOperations) {
    this.vaultOperations = vaultOperations;
  }

  private static SecretKeySpec createKeySpec(String rawKey) {
    return new SecretKeySpec(BASE64_DECODER.decode(rawKey), ALGORITHM_ENCRYPTION);
  }

  private static Cipher createCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
    return Cipher.getInstance(ALGORITHM_TRANSFORMATION);
  }

  VaultTransitCipher generate() throws NoSuchPaddingException, NoSuchAlgorithmException {
    // TODO: instead of reading vault key create data key
    String keyVersion = getKeyVersion();
    String rawKey = getRawKeyFromVault();
    SecretKeySpec secretKeySpec = createKeySpec(rawKey);
    Cipher cipher = createCipher();
    return new VaultTransitCipher(keyVersion, secretKeySpec, cipher);
  }

  private String getKeyVersion() {
    return String.valueOf(getKeyMetadataFromVault().getLatestVersion());
  }

  private VaultTransitKey getKeyMetadataFromVault() {
    return Preconditions.checkNotNull(
        vaultOperations
            .opsForTransit(TransitPath.ENCRYPTION.getPath())
            .getKey(DataType.USER_DATA.getKeyName()));
  }

  private String getRawKeyFromVault() {
    return Preconditions.checkNotNull(
            vaultOperations
                .opsForTransit(TransitPath.ENCRYPTION.getPath())
                .exportKey(DataType.USER_DATA.getKeyName(), TransitKeyType.ENCRYPTION_KEY))
        .getKeys()
        .get(getKeyVersion());
  }
}
