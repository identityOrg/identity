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

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class UserInfoTest extends HtmlPageTestBase {

    @Test
    public void testUserInfo() throws IOException, ParseException {
        ResourceOwnerPasswordCredentialsGrant grant =
                new ResourceOwnerPasswordCredentialsGrant("admin", new Secret("admin"));

        ClientAuthentication clientAuth = new ClientSecretBasic(clientInformation.getID(), clientInformation.getSecret());
        Scope scope = Scope.parse("openid profile");
        TokenRequest tokenRequest = new TokenRequest(getTokenURI(), clientAuth, grant, scope);

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

        assertTrue(tokenResponse.indicatesSuccess());

        UserInfoRequest userInfoRequest = new UserInfoRequest(getUserInfoURI(),
                tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken());

        UserInfoResponse userInfoResponse = UserInfoResponse.parse(userInfoRequest.toHTTPRequest().send());

        assertTrue(userInfoResponse.indicatesSuccess());
        UserInfo userInfo = userInfoResponse.toSuccessResponse().getUserInfo();
        assertNotNull(userInfo.getBirthdate());
    }
}
