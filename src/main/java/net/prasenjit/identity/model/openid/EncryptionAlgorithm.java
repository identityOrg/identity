package net.prasenjit.identity.model.openid;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum EncryptionAlgorithm {
    @JsonProperty("RSA-OAEP")
    RSA_OAEP,
    @JsonProperty("RSA-OAEP-256")
    RSA_OAEP_256
}
