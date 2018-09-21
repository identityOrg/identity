package net.prasenjit.identity.oauth;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ClientCredentialTest extends HtmlPageTestBase {

    @Test
    public void clientCredentialGrant() throws ParseException, IOException {
        ClientAuthentication clientAuth = new ClientSecretBasic(clientInformation.getID(), clientInformation.getSecret());
        ClientCredentialsGrant grant = new ClientCredentialsGrant();
        Scope scope = Scope.parse("scope1");
        TokenRequest tokenRequest = new TokenRequest(getTokenURI(), clientAuth, grant, scope);

        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

        assertTrue(tokenResponse.indicatesSuccess());

        assertNotNull(tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken());
    }

}
