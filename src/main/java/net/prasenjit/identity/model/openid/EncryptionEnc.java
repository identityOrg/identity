package net.prasenjit.identity.model.openid;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.EncryptionMethod;
import lombok.Getter;

public enum EncryptionEnc {
    @JsonProperty("A128CBC-HS256")
    A128CBC_HS256(EncryptionMethod.A128CBC_HS256),
    A128GCM(EncryptionMethod.A128GCM);

    @Getter
    private EncryptionMethod value;

    EncryptionEnc(EncryptionMethod value) {
        this.value = value;
    }
}
