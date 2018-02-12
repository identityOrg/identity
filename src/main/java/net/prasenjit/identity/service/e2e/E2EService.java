package net.prasenjit.identity.service.e2e;

import com.nimbusds.jose.jwk.RSAKey;
import net.prasenjit.crypto.endtoend.RsaEncryptorBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.annotation.SessionScope;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

@Service
@SessionScope
public class E2EService implements Serializable {
    private static final long serialVersionUID = -5325012556475091825L;

    private KeyPair keyPair;

    private E2eStatus status = E2eStatus.NONE;

    private transient Object sync = new Object();

    @Autowired
    private HttpSession httpSession;

    public void generateAsymmetricKey() {
        synchronized (sync) {
            if (status == E2eStatus.SYMMETRIC) {
                throw new RuntimeException("E2E already initialized with symmetric key");
            } else if (status == E2eStatus.NONE) {
                try {
                    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                    status = E2eStatus.ASYMMETRIC;
                } catch (NoSuchAlgorithmException e) {
                    ReflectionUtils.rethrowRuntimeException(e);
                }
            }
        }
    }

    public RSAKey getAsymmetricKey() {
        generateAsymmetricKey();
        RSAKey.Builder keyBuilder = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyID(httpSession.getId());
        return keyBuilder.build();
    }

    public String encrypt(String data) {
        if (status == E2eStatus.ASYMMETRIC) {
            return RsaEncryptorBuilder.client(keyPair.getPublic()).encrypt(data);
        } else {
            throw new RuntimeException("Cryptography not initialized");
        }
    }

    public String decrypt(String data) {
        if (status == E2eStatus.ASYMMETRIC) {
            return RsaEncryptorBuilder.server(keyPair.getPrivate()).decrypt(data);
        } else {
            throw new RuntimeException("Cryptography not initialized");
        }
    }
}
