/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.identity.controller.e2e;

import com.nimbusds.jose.jwk.RSAKey;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;

@Tag(name = "e2e", description = "End to end encryption API's")
public interface E2EApi {

    @Operation(summary = "Asymmetric E2E", description = "Initializes the Asymmetric E2E for the" +
            " session and returns the public exponent and modulus of RSA key pair")
//    @ApiResponses(
//            @ApiResponse(code = 200, message = "Success",
//                    responseHeaders = @ResponseHeader(name = "X-Session-Id",
//                            description = "Current session id associated with response", response = String.class))
//    )
    RSAKey asymmetricE2E(Authentication authentication);

    @Operation(summary = "Encrypt Text", description = "Encrypt text data using RSA Public Key")
//    @ApiResponses(
//            @ApiResponse(code = 200, message = "Success",
//                    responseHeaders = @ResponseHeader(name = "X-Session-Id",
//                            description = "Current session id associated with response", response = String.class))
//    )
    String encrypt(String data, Authentication authentication);

    @Operation(summary = "Decrypt Text", description = "Decrypt text data using RSA Private Key")
//    @ApiResponses(
//            @ApiResponse(code = 200, message = "Success",
//                    responseHeaders = @ResponseHeader(name = "X-Session-Id",
//                            description = "Current session id associated with response", response = String.class))
//    )
    String decrypt(String data, Authentication authentication);

}