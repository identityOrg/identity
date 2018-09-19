package net.prasenjit.identity.openid;

import com.gargoylesoftware.htmlunit.util.Cookie;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.*;
import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Test;

import java.net.URI;
import java.time.LocalDateTime;

import static org.junit.Assert.assertFalse;

/**
 * Created by PRASENJIT-NET on 8/9/2018.
 */
public class OpenIDPromtTest extends HtmlPageTestBase {

    @Test
    public void testPromptLogin() throws Exception {
        State state = new State();
        Nonce nonce = new Nonce();
        AuthenticationRequest request = new AuthenticationRequest.Builder(ResponseType.parse("code"),
                new Scope("openid"),
                clientID,
                getRedirectURI())
                .nonce(nonce)
                .prompt(Prompt.parse("login"))
                .state(state)
                .endpointURI(getAuthorizeURI()).build();

        clearContext(true, true);

        String cookieToken = codeFactory.createCookieToken("admin", LocalDateTime.now());
        webClient.getCookieManager()
                .addCookie(new Cookie(
                        metadataService.findOIDCConfiguration().getIssuer().getValue(),
                        "S_CONTEXT", cookieToken));

        loginForConsentPage(request.toURI(), "admin", "admin");
    }

    @Test
    public void testPromptNone() throws Exception {
        State state = new State();
        Nonce nonce = new Nonce();
        AuthenticationRequest request = new AuthenticationRequest.Builder(ResponseType.parse("code"),
                new Scope("openid"),
                clientID,
                getRedirectURI())
                .nonce(nonce)
                .prompt(Prompt.parse("none"))
                .state(state)
                .endpointURI(getAuthorizeURI()).build();

        clearContext(true, true);

        setRememberLogin("admin");

        createUserConsent("admin", "openid");

        loginForURI(request.toURI(), "admin", "admin");
    }

    @Test
    public void testPromptNoneError() throws Exception {
        State state = new State();
        Nonce nonce = new Nonce();
        AuthenticationRequest request = new AuthenticationRequest.Builder(ResponseType.parse("code"),
                new Scope("openid"),
                clientID,
                getRedirectURI())
                .nonce(nonce)
                .prompt(Prompt.parse("none"))
                .state(state)
                .endpointURI(getAuthorizeURI()).build();

        clearContext(true, true);

        URI responseURI = followForError(request.toURI());

        AuthenticationResponse response = AuthenticationResponseParser.parse(responseURI);

        assertFalse(response.indicatesSuccess());
    }

    @Test
    public void testPromptNoneErrorConsentMust() throws Exception {
        State state = new State();
        Nonce nonce = new Nonce();
        AuthenticationRequest request = new AuthenticationRequest.Builder(ResponseType.parse("code"),
                new Scope("openid"),
                clientID,
                getRedirectURI())
                .nonce(nonce)
                .prompt(Prompt.parse("none"))
                .state(state)
                .endpointURI(getAuthorizeURI()).build();

        clearContext(true, true);

        URI responseURI = loginForURI(request.toURI(), "admin", "admin");

        AuthenticationResponse response = AuthenticationResponseParser.parse(responseURI);

        assertFalse(response.indicatesSuccess());
    }

    @Test
    public void testPromptConsent() throws Exception {
        State state = new State();
        Nonce nonce = new Nonce();
        AuthenticationRequest request = new AuthenticationRequest.Builder(ResponseType.parse("code"),
                new Scope("openid"),
                clientID,
                getRedirectURI())
                .nonce(nonce)
                .prompt(Prompt.parse("consent"))
                .state(state)
                .endpointURI(getAuthorizeURI()).build();

        clearContext(true, true);

        setRememberLogin("admin");

        createUserConsent("admin", "openid");

        loginForConsentPage(request.toURI(), "admin", "admin");
    }
}
