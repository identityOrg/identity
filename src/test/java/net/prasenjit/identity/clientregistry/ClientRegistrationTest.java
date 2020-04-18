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

package net.prasenjit.identity.clientregistry;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.client.ClientDeleteRequest;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationResponseParser;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientUpdateRequest;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class ClientRegistrationTest extends HtmlPageTestBase {

    @Test
    public void testRegistrationSuccess() throws ParseException, IOException {
        URI uri = oidcConfiguration.getRegistrationEndpointURI();
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setName("Unit Test Client");
        ClientAuthentication clientAuth = new ClientSecretBasic(clientInformation.getID(),
                clientInformation.getSecret());
        ClientCredentialsGrant grant = new ClientCredentialsGrant();
        Scope scope = Scope.parse("scope1");
        TokenRequest tokenRequest = new TokenRequest(getTokenURI(), clientAuth, grant, scope);

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
        BearerAccessToken bearerAccessToken = tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken();
        OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(uri, metadata, bearerAccessToken);

        ClientRegistrationResponse response = OIDCClientRegistrationResponseParser
                .parse(request.toHTTPRequest().send());

        assertTrue(response.indicatesSuccess());

        ClientInformation info = response.toSuccessResponse().getClientInformation();
        OIDCClientMetadata clientMetadata = (OIDCClientMetadata) info.getMetadata();

        JWSAlgorithm alg = clientMetadata.getIDTokenJWSAlg();

        assertNotNull(alg);
        assertThat(JWSAlgorithm.RS256, is(alg));

        clientMetadata.setIDTokenJWSAlg(JWSAlgorithm.RS384);

        // check get information
        OIDCClientUpdateRequest updateRequest = new OIDCClientUpdateRequest(info.getRegistrationURI(), info.getID(),
                bearerAccessToken, clientMetadata, info.getSecret());

        response = OIDCClientRegistrationResponseParser.parse(updateRequest.toHTTPRequest().send());

        assertTrue(response.indicatesSuccess());

        info = response.toSuccessResponse().getClientInformation();
        clientMetadata = (OIDCClientMetadata) info.getMetadata();

        alg = clientMetadata.getIDTokenJWSAlg();

        assertNotNull(alg);
        assertThat(JWSAlgorithm.RS384, is(alg));

        ClientReadRequest readRequest = new ClientReadRequest(info.getRegistrationURI(), bearerAccessToken);

        response = OIDCClientRegistrationResponseParser.parse(readRequest.toHTTPRequest().send());

        assertTrue(response.indicatesSuccess());

        info = response.toSuccessResponse().getClientInformation();
        clientMetadata = (OIDCClientMetadata) info.getMetadata();

        alg = clientMetadata.getIDTokenJWSAlg();

        assertNotNull(alg);
        assertThat(JWSAlgorithm.RS384, is(alg));

        ClientDeleteRequest deleteRequest = new ClientDeleteRequest(info.getRegistrationURI(), bearerAccessToken);

        HTTPResponse httpResponse = deleteRequest.toHTTPRequest().send();

        assertThat(200, is(httpResponse.getStatusCode()));

        response = OIDCClientRegistrationResponseParser.parse(readRequest.toHTTPRequest().send());

        assertFalse(response.indicatesSuccess());
    }
}
