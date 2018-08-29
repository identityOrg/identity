package net.prasenjit.identity.model.openid;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.JWEAlgorithm;
import lombok.Getter;

public enum EncryptionAlgorithm {
    @JsonProperty("RSA-OAEP")
    @Deprecated
    RSA_OAEP(JWEAlgorithm.RSA_OAEP),

    @JsonProperty("RSA-OAEP-256")
    RSA_OAEP_256(JWEAlgorithm.RSA_OAEP_256);

    @Getter
    private JWEAlgorithm value;

    EncryptionAlgorithm(JWEAlgorithm value) {
        this.value = value;
    }
}
