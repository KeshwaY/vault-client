package space.keshway.vault.client.model;

import java.util.Arrays;
import lombok.Getter;

@Getter
public enum DataType {
  USER_DATA("user-data");

  private final String keyName;

  DataType(String keyName) {
    this.keyName = keyName;
  }

  public static DataType fromKeyName(String keyName) {
    return Arrays.stream(DataType.values())
        .filter(t -> t.keyName.equals(keyName))
        .findFirst()
        .orElseThrow();
  }
}
