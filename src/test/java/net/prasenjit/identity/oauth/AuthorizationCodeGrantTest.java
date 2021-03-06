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

package net.prasenjit.identity.oauth;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.id.State;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AuthorizationCodeGrantTest extends HtmlPageTestBase {

    @Test
    public void testSuccess() throws Exception {

        // The requested scope values for the token
        Scope scope = new Scope("scope1", "scope2");

        // Generate random state string for pairing the response to the request
        State state = new State();

        // Build the request
        AuthorizationRequest request = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientInformation.getID())
                .scope(scope)
                .state(state)
                .redirectionURI(getRedirectURI())
                .endpointURI(getAuthorizeURI())
                .build();

        // Use this URI to send the end-user's browser to the server
        URI authURI = request.toURI();

        clearContext(true, true);

        HtmlPage htmlPage = loginForConsentPage(authURI, "admin", "admin");
        URI uri = acceptAllConsent(htmlPage);

        // Parse the authorisation response from the callback URI
        AuthorizationResponse response = AuthorizationResponse.parse(uri);

        assertTrue(response.indicatesSuccess());

        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) response;

        assertTrue(state.equals(successResponse.getState()));

        // Retrieve the authorisation code, to be used later to exchange the code for
        // an access token at the token endpoint of the server
        AuthorizationCode code = successResponse.getAuthorizationCode();

        assertNotNull(code);

        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, getRedirectURI());

        ClientAuthentication clientAuth = new ClientSecretBasic(clientInformation.getID(), clientInformation.getSecret());


        // Make the token request
        TokenRequest tokenRequest = new TokenRequest(getTokenURI(), clientAuth, codeGrant);

        TokenResponse tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());

        assertTrue(tokenResponse.indicatesSuccess());

        assertNotNull(tokenResponse.toSuccessResponse().getTokens().getAccessToken());
    }

    @Test
    public void testSuccessWithoutStateAndRedirectURI() throws Exception {

        // The requested scope values for the token
        Scope scope = new Scope("scope1", "scope2");

        // Build the request
        AuthorizationRequest request = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientInformation.getID())
                .scope(scope)
                .endpointURI(getAuthorizeURI())
                .build();

        // Use this URI to send the end-user's browser to the server
        URI authURI = request.toURI();

        clearContext(true, true);

        HtmlPage htmlPage = loginForConsentPage(authURI, "admin", "admin");
        URI uri = acceptAllConsent(htmlPage);

        // Parse the authorisation response from the callback URI
        AuthorizationResponse response = AuthorizationResponse.parse(uri);

        assertTrue(response.indicatesSuccess());

        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) response;

        // Retrieve the authorisation code, to be used later to exchange the code for
        // an access token at the token endpoint of the server
        AuthorizationCode code = successResponse.getAuthorizationCode();

        assertNotNull(code);

        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, null);

        ClientAuthentication clientAuth = new ClientSecretBasic(clientInformation.getID(), clientInformation.getSecret());


        // Make the token request
        TokenRequest tokenRequest = new TokenRequest(getTokenURI(), clientAuth, codeGrant);

        TokenResponse tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());

        assertTrue(tokenResponse.indicatesSuccess());

        assertNotNull(tokenResponse.toSuccessResponse().getTokens().getAccessToken());
    }
}
