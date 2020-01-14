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

package net.prasenjit.identity.openid;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TokenEPTest extends HtmlPageTestBase {

    @Override
    protected void configureClient(OIDCClientMetadata metadata) throws JOSEException, ParseException {
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
        metadata.setTokenEndpointAuthJWSAlg(JWSAlgorithm.HS256);
    }

    @Test
    public void testClientCredentials() throws JOSEException, IOException, ParseException {
        ClientSecretJWT auth = new ClientSecretJWT(clientInformation.getID(), getTokenURI(), JWSAlgorithm.HS256, clientInformation.getSecret());
        ClientCredentialsGrant grant = new ClientCredentialsGrant();
        TokenRequest tokenRequest = new TokenRequest(getTokenURI(), auth, grant);

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

        assertTrue(tokenResponse.indicatesSuccess());

        assertNotNull(tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken());
    }
}
