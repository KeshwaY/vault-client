package space.keshway.vault.client.encryption;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;
import javax.crypto.NoSuchPaddingException;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultTransitOperations;
import org.springframework.vault.support.AbstractResult;
import org.springframework.vault.support.Ciphertext;
import org.springframework.vault.support.Plaintext;
import org.springframework.vault.support.VaultEncryptionResult;
import space.keshway.vault.client.model.Data;

@Service
final class EncryptionServiceImpl implements EncryptionService {

  private final VaultTransitOperations vaultOps;
  private final VaultTransitCipher cipher;

  EncryptionServiceImpl(
      VaultOperations vaultOperations, VaultTransitCipherGenerator vaultTransitCipherGenerator)
      throws NoSuchPaddingException, NoSuchAlgorithmException {
    this.vaultOps = vaultOperations.opsForTransit(TransitPath.ENCRYPTION.getPath());
    this.cipher = vaultTransitCipherGenerator.generate();
  }

  private static List<Plaintext> convertToPlaintext(List<String> strings) {
    return strings.stream().map(Plaintext::of).toList();
  }

  private static List<Ciphertext> convertToCiphertext(List<String> strings) {
    return strings.stream().map(Ciphertext::of).toList();
  }

  // TODO: get rid of streams, introduce immutables
  @Override
  public Data encrypt(Data data) {
    return new Data(
        data.type(),
        vaultOps.encrypt(data.type().getKeyName(), convertToPlaintext(data.values())).stream()
            .map(VaultEncryptionResult::get)
            .filter(Objects::nonNull)
            .map(Ciphertext::getCiphertext)
            .toList());
  }

  @Override
  public Data encryptLocally(Data data) {
    return new Data(data.type(), cipher.encrypt(data.values()).stream().toList());
  }

  @Override
  public Data decrypt(Data data) {
    return new Data(
        data.type(),
        vaultOps.decrypt(data.type().getKeyName(), convertToCiphertext(data.values())).stream()
            .map(AbstractResult::get)
            .filter(Objects::nonNull)
            .map(Plaintext::asString)
            .toList());
  }

  @Override
  public Data decryptLocally(Data data) {
    return new Data(data.type(), cipher.decrypt(data.values()).stream().toList());
  }
}
