package net.prasenjit.identity.model.openid;

import com.nimbusds.jose.JWSAlgorithm;
import lombok.Getter;

public enum SignatureAlgorithm {
    RS256(JWSAlgorithm.RS256), RS384(JWSAlgorithm.RS384), RS512(JWSAlgorithm.RS512),
    ES256(JWSAlgorithm.ES256), ES384(JWSAlgorithm.ES384), ES512(JWSAlgorithm.ES512);
    @Getter
    private JWSAlgorithm value;

    SignatureAlgorithm(JWSAlgorithm value) {
        this.value = value;
    }
}
