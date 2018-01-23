package net.prasenjit.identity.model;

import lombok.Data;

@Data
public class AsymmetricE2EResponse {
    private final String publicExponent;
    private final String modulus;
}
