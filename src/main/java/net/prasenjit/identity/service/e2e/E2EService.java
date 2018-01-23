package net.prasenjit.identity.service.e2e;

import net.prasenjit.crypto.endtoend.RsaEncryptorBuilder;
import net.prasenjit.identity.model.AsymmetricE2EResponse;
import org.springframework.stereotype.Service;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.annotation.SessionScope;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

@Service
@SessionScope
public class E2EService implements Serializable {

    private KeyPair keyPair;

    private E2eStatus status = E2eStatus.NONE;

    private transient Object sync = new Object();

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

    public AsymmetricE2EResponse getAsymmetricKey() {
        generateAsymmetricKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        BigInteger publicExponent = publicKey.getPublicExponent();
        BigInteger modulus = publicKey.getModulus();
        return new AsymmetricE2EResponse(publicExponent.toString(16), modulus.toString(16));
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
