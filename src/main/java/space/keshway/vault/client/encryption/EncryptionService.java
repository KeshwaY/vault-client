package space.keshway.vault.client.encryption;

import space.keshway.vault.client.model.Data;

public interface EncryptionService {
  Data encrypt(Data data);

  Data encryptLocally(Data data);

  Data decrypt(Data data);

  Data decryptLocally(Data data);
}
