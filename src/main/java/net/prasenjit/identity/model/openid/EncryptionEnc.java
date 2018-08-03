package net.prasenjit.identity.model.openid;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum EncryptionEnc {
    @JsonProperty("A128CBC-HS256")
    A128CBC_HS256,
    A128GCM
}
