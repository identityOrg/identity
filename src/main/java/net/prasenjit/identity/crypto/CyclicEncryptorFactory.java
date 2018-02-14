package net.prasenjit.identity.crypto;

import java.time.LocalDateTime;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.crypto.impl.AesEncryptor;
import net.prasenjit.crypto.store.CryptoKeyFactory;
import net.prasenjit.identity.properties.IdentityProperties;

@Component
@RequiredArgsConstructor
public class CyclicEncryptorFactory {
	private final CryptoKeyFactory keyFactory;
	private final IdentityProperties identityProperties;

	public TextEncryptor createEncryptor(LocalDateTime dateTime) {
		int dayOfMonth = dateTime.getDayOfMonth();
		int cycle = dayOfMonth % 5;
		String cyclePassword = identityProperties.getCryptoProperties().getCyclePassword().get(cycle);
		SecretKey secretKey = keyFactory.getSecretKey("cycle-" + cycle, cyclePassword.toCharArray());
		return new AesEncryptor(secretKey);
	}
}
