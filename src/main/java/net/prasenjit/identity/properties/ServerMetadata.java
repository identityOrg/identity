package net.prasenjit.identity.properties;

import lombok.Data;

@Data
public class ServerMetadata {
    /**
     * REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer
     * Identifier. If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value
     * returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
     */
    private String issuer;

}
