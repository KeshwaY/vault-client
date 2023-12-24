package space.keshway.vault.client.encryption;

import lombok.Getter;

@Getter
enum TransitPath {
  ENCRYPTION("encryption");

  private final String path;

  TransitPath(String path) {
    this.path = path;
  }
}
