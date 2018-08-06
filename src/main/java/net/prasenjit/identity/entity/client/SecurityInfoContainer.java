package net.prasenjit.identity.entity.client;

import lombok.Data;
import net.prasenjit.identity.model.openid.EncryptionAlgorithm;
import net.prasenjit.identity.model.openid.EncryptionEnc;
import net.prasenjit.identity.model.openid.SignatureAlgorithm;
import net.prasenjit.identity.security.TokenEPAuthMethod;

@Data
public class SecurityInfoContainer {
    private SignatureAlgorithm idTokenSigningAlgo;
    private EncryptionAlgorithm idTokenEncryptionAlgo;
    private EncryptionEnc idTokenEncryptionEnc;

    private SignatureAlgorithm userInfoResponseSigningAlgo;
    private EncryptionAlgorithm userInfoResponseEncryptionAlgo;
    private EncryptionEnc userInfoResponseEncryptionEnc;

    private SignatureAlgorithm requestObjectSigningAlgo;
    private EncryptionAlgorithm requestObjectEncryptionAlgo;
    private EncryptionEnc requestObjectEncryptionEnc;

    private TokenEPAuthMethod tokenEPAuthMethod;
    private SignatureAlgorithm tokenEPSigningAlgo;
}
