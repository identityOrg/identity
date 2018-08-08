package net.prasenjit.identity.openid;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.Nonce;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.net.URI;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class OpenIDTestWithSDK extends HtmlPageTestBase {

    @Test
    public void testOpenIDSimpleSuccess() throws Exception {
        // The client identifier provisioned by the server
        ClientID clientID = new ClientID("client");
        Secret clientSecret = new Secret("client");

        // Generate random state string for pairing the response to the request
        State state = new State();

        // Generate nonce
        Nonce nonce = new Nonce();

        // Compose the request (in code flow)
        AuthenticationRequest req = new AuthenticationRequest(
                getAuthorizeURI(),
                new ResponseType("code"),
                Scope.parse("openid"),
                clientID,
                getRedirectURI(),
                state,
                nonce);

        clearContext(true, true);

        HtmlPage consentPage = loginForConsentPage(req.toURI(), "admin", "admin");

        URI responseUri = acceptAllConcent(consentPage);

        AuthenticationResponse response = AuthenticationResponseParser.parse(responseUri);
        assertTrue(response.indicatesSuccess());
        assertTrue(response.toSuccessResponse().getAuthorizationCode() != null);
        assertTrue(state.equals(response.toSuccessResponse().getState()));


        TokenResponse tokenResponse = executeTokenResponse(clientID, clientSecret, response);

        assertTrue(tokenResponse.indicatesSuccess());
        assertNotNull(tokenResponse.toSuccessResponse().getTokens().getAccessToken());
    }
}
