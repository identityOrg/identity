package net.prasenjit.identity.openid;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.Nonce;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class OpenIDTestWithSDK extends HtmlPageTestBase {

    @Test
    public void testOpenIDSimpleSuccess() throws Exception {

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

        URI responseUri = acceptAllConsent(consentPage);

        AuthenticationResponse response = AuthenticationResponseParser.parse(responseUri);
        assertTrue(response.indicatesSuccess());
        assertTrue(response.toSuccessResponse().getAuthorizationCode() != null);
        assertTrue(state.equals(response.toSuccessResponse().getState()));


        TokenResponse tokenResponse = executeTokenResponse(clientID, clientSecret, response);

        assertTrue(tokenResponse.indicatesSuccess());
        assertNotNull(tokenResponse.toSuccessResponse().getTokens().getAccessToken());
    }

    @Test
    public void testImplicitIDTokenResponse() throws Exception {

        // Generate random state string for pairing the response to the request
        State state = new State();

        // Generate nonce
        Nonce nonce = new Nonce();

        // Compose the request (in code flow)
        AuthenticationRequest req = new AuthenticationRequest(
                getAuthorizeURI(),
                new ResponseType("id_token"),
                Scope.parse("openid"),
                clientID,
                getRedirectURI(),
                state,
                nonce);

        clearContext(true, true);

        HtmlPage consentPage = loginForConsentPage(req.toURI(), "admin", "admin");

        URI responseUri = acceptAllConsent(consentPage);

        AuthenticationResponse response = AuthenticationResponseParser.parse(responseUri);
        assertTrue(response.indicatesSuccess());
        assertNotNull(response.toSuccessResponse().getIDToken());
    }

    @Test
    public void testImplicitTokenResponse() throws Exception {

        // Generate random state string for pairing the response to the request
        State state = new State();

        // Generate nonce
        Nonce nonce = new Nonce();

        // Compose the request (in code flow)
        AuthenticationRequest req = new AuthenticationRequest(
                getAuthorizeURI(),
                new ResponseType("id_token", "token"),
                Scope.parse("openid"),
                clientID,
                getRedirectURI(),
                state,
                nonce);

        clearContext(true, true);

        HtmlPage consentPage = loginForConsentPage(req.toURI(), "admin", "admin");

        URI responseUri = acceptAllConsent(consentPage);

        AuthenticationResponse response = AuthenticationResponseParser.parse(responseUri);
        assertTrue(response.indicatesSuccess());
        assertNotNull(response.toSuccessResponse().getAccessToken());
        assertNotNull(response.toSuccessResponse().getIDToken());
        assertTrue(state.equals(response.getState()));
    }
}
