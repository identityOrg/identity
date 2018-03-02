package net.prasenjit.identity.model;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
public class AsymmetricE2EResponse {
    @ApiModelProperty(value = "Public exponent of RSA Public key HEX encoded", required = true)
    private final String publicExponent;
    @ApiModelProperty(value = "Modulus of RSA Public key HEX encoded", required = true)
    private final String modulus;
}
