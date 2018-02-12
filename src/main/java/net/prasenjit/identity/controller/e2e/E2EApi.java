package net.prasenjit.identity.controller.e2e;

import com.nimbusds.jose.jwk.RSAKey;
import io.swagger.annotations.*;

@Api(value = "E2E", tags = "e2e", description = "End to end encryption API's")
public interface E2EApi {

    @ApiOperation(value = "Asymmetric E2E", notes = "Initializes the Asymmetric E2E for the" +
            " session and returns the public exponent and modulus of RSA key pair")
    @ApiResponses(
            @ApiResponse(code = 200, message = "Success",
                    responseHeaders = @ResponseHeader(name = "X-Session-Id",
                            description = "Current session id associated with response", response = String.class))
    )
    RSAKey asymmetricE2E();

    @ApiOperation(value = "Encrypt Text", notes = "Encrypt text data using RSA Public Key")
    @ApiResponses(
            @ApiResponse(code = 200, message = "Success",
                    responseHeaders = @ResponseHeader(name = "X-Session-Id",
                            description = "Current session id associated with response", response = String.class))
    )
    String encrypt(String data);

    @ApiOperation(value = "Decrypt Text", notes = "Decrypt text data using RSA Private Key")
    @ApiResponses(
            @ApiResponse(code = 200, message = "Success",
                    responseHeaders = @ResponseHeader(name = "X-Session-Id",
                            description = "Current session id associated with response", response = String.class))
    )
    String decrypt(String data);

}