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

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;

public class IntrospectionRevocationTest extends HtmlPageTestBase {

    @Test
    public void testSuccess() throws IOException, ParseException {
        ClientAuthentication clientAuth = new ClientSecretBasic(clientInformation.getID(), clientInformation.getSecret());
        AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("admin", new Secret("admin"));
        Scope scope = Scope.parse("openid");
        TokenRequest passwordTokenRequest = new TokenRequest(getTokenURI(), clientAuth, grant, scope);

        TokenResponse response = TokenResponse.parse(passwordTokenRequest.toHTTPRequest().send());

        AccessToken accessToken = response.toSuccessResponse().getTokens().getAccessToken();
        TokenIntrospectionRequest introspectionRequest = new TokenIntrospectionRequest(getIntrospectionURI(),
                clientAuth, accessToken);

        TokenIntrospectionResponse introspectionResponse = TokenIntrospectionResponse.parse(
                introspectionRequest.toHTTPRequest().send());

        assertNotNull(introspectionResponse);
        assertTrue(introspectionResponse.indicatesSuccess());

        TokenRevocationRequest revocationRequest = new TokenRevocationRequest(getRevocationURI(), clientAuth, accessToken);

        HTTPResponse httpResponse = revocationRequest.toHTTPRequest().send();

        assertEquals(200, httpResponse.getStatusCode());

        introspectionResponse = TokenIntrospectionResponse.parse(introspectionRequest.toHTTPRequest().send());

        assertTrue(introspectionResponse.indicatesSuccess());

        TokenIntrospectionSuccessResponse successResponse = (TokenIntrospectionSuccessResponse) introspectionResponse;

        assertFalse(successResponse.isActive());
    }

    @Test
    public void testSuccessWithRefreshTokenRevoke() throws IOException, ParseException {

        // get a token
        ClientAuthentication clientAuth = new ClientSecretBasic(clientInformation.getID(), clientInformation.getSecret());
        AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("admin", new Secret("admin"));
        Scope scope = Scope.parse("openid");
        TokenRequest passwordTokenRequest = new TokenRequest(getTokenURI(), clientAuth, grant, scope);
        TokenResponse response = TokenResponse.parse(passwordTokenRequest.toHTTPRequest().send());

        // refresh the token
        RefreshToken parentRefreshToken = response.toSuccessResponse().getTokens().getRefreshToken();
        AuthorizationGrant refreshGrant = new RefreshTokenGrant(parentRefreshToken);
        TokenRequest refreshTokenRequest = new TokenRequest(getTokenURI(), clientAuth, refreshGrant);
        TokenResponse refreshedToken = TokenResponse.parse(refreshTokenRequest.toHTTPRequest().send());

        // introspect
        TokenIntrospectionRequest introspectionRequest = new TokenIntrospectionRequest(getIntrospectionURI(),
                clientAuth, refreshedToken.toSuccessResponse().getTokens().getAccessToken());
        TokenIntrospectionResponse introspectionResponse = TokenIntrospectionResponse.parse(introspectionRequest.toHTTPRequest().send());
        assertNotNull(introspectionResponse);
        assertTrue(introspectionResponse.indicatesSuccess());
        TokenIntrospectionSuccessResponse successResponse = (TokenIntrospectionSuccessResponse) introspectionResponse;
        assertTrue(successResponse.isActive());

        // revoke refreshed token
        TokenRevocationRequest revocationRequest = new TokenRevocationRequest(getRevocationURI(), clientAuth, parentRefreshToken);
        HTTPResponse httpResponse = revocationRequest.toHTTPRequest().send();
        assertEquals(200, httpResponse.getStatusCode());

        // introspect again
        introspectionResponse = TokenIntrospectionResponse.parse(introspectionRequest.toHTTPRequest().send());
        assertNotNull(introspectionResponse);
        assertTrue(introspectionResponse.indicatesSuccess());
        successResponse = (TokenIntrospectionSuccessResponse) introspectionResponse;
        assertFalse(successResponse.isActive());
    }
}
