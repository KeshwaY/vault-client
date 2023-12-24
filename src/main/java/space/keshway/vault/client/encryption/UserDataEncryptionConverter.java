package space.keshway.vault.client.encryption;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Convert;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import space.keshway.vault.client.model.Data;
import space.keshway.vault.client.model.DataType;

@Convert
@RequiredArgsConstructor
public final class UserDataEncryptionConverter implements AttributeConverter<String, String> {

  private static final int LIST_FIRST_VALUE = 0;

  private final EncryptionService encryptionService;

  @Override
  public String convertToDatabaseColumn(String attribute) {
    return Optional.ofNullable(attribute)
        .map(
            attr ->
                encryptionService
                    .encryptLocally(new Data(DataType.USER_DATA, List.of(attr)))
                    .values()
                    .get(LIST_FIRST_VALUE))
        .orElse(null);
  }

  @Override
  public String convertToEntityAttribute(String dbData) {
    return Optional.ofNullable(dbData)
        .map(
            data ->
                encryptionService
                    .decryptLocally(new Data(DataType.USER_DATA, List.of(data)))
                    .values()
                    .get(LIST_FIRST_VALUE))
        .orElse(null);
  }
}
