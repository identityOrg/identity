package net.prasenjit.identity.config;

import net.prasenjit.crypto.impl.SshaPasswordEncryptor;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CryptoPasswordEncoder implements PasswordEncoder {

    private SshaPasswordEncryptor passwordEncryptor = new SshaPasswordEncryptor();

    @Override
    public String encode(CharSequence rawPassword) {
        return passwordEncryptor.encrypt(rawPassword.toString());
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return passwordEncryptor.testMatch(rawPassword.toString(), encodedPassword);
    }
}
