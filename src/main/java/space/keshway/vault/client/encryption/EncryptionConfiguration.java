package space.keshway.vault.client.encryption;

import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.core.VaultOperations;

@Configuration
public class EncryptionConfiguration {

  @Bean
  VaultTransitCipherGenerator cipherGenerator(ApplicationContext applicationContext) {
    return new VaultTransitCipherGenerator(applicationContext.getBean(VaultOperations.class));
  }

  @Bean
  EncryptionService encryptionService(
      ApplicationContext applicationContext, VaultTransitCipherGenerator transitCipherGenerator)
      throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new EncryptionServiceImpl(
        applicationContext.getBean(VaultOperations.class), transitCipherGenerator);
  }
}
