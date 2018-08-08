package net.prasenjit.identity;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import net.prasenjit.identity.repository.UserConsentRepository;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.htmlunit.MockMvcWebClientBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class HtmlPageTestBase {

    private static final String TOKEN_URL = "http://localhost/oauth/token";
    private static final String REDIRECT_URL = "http://localhost:4200/callback";
    private static final String AUTHORIZE_URL = "http://localhost/oauth/authorize";
    private static final String ISSUER_URL = "http://localhost";
    @Autowired
    protected WebApplicationContext context;
    protected WebClient webClient;
    protected MockMvc mockMvc;
    @Autowired
    protected UserConsentRepository userConsentRepository;
    @LocalServerPort
    protected int port;
    // The client identifier provisioned by the server
    protected ClientID clientID = new ClientID("client");
    protected Secret clientSecret = new Secret("client");

    @Before
    public void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();

        webClient = MockMvcWebClientBuilder
                .mockMvcSetup(mockMvc)
                // for illustration only - defaults to ""
                .contextPath("")
                // By default MockMvc is used for localhost only;
                // the following will use MockMvc for example.com and example.org as well
                // .useMockMvcForHosts("example.com","example.org")
                .build();
    }


    protected URI acceptAllConcent(HtmlPage authHtml) throws IOException, URISyntaxException {
        List<HtmlButton> validButtons = authHtml.getFormByName("auth").getButtonsByName("valid");
        for (HtmlButton b : validButtons) {
            if ("true".equals(b.getValueAttribute())) {
                try {
                    b.click();
                } catch (FailingHttpStatusCodeException ex) {
                    assertEquals(404, ex.getStatusCode());
                    return ex.getResponse().getWebRequest().getUrl().toURI();
                }
            }
        }
        throw new RuntimeException("Could not accept all consent");
    }

    protected HtmlPage loginForConsentPage(URI startUrl, String username, String password) throws IOException {


        Page page = webClient.getPage(startUrl.toString());
        assertTrue(page.isHtmlPage());
        HtmlPage loginPage = (HtmlPage) page;
        HtmlForm loginForm = loginPage.getFormByName("login");
        loginForm.getInputByName("username").setValueAttribute(username);
        loginForm.getInputByName("password").setValueAttribute(password);
        Page nextPage = loginForm.getButtonByName("submit").click();
        assertTrue(nextPage.isHtmlPage());
        return (HtmlPage) nextPage;
    }

    protected TokenResponse executeTokenResponse(ClientID clientID, Secret clientSecret, AuthenticationResponse response) throws ParseException, IOException {
        AuthorizationGrant codeGrant = new AuthorizationCodeGrant(response.toSuccessResponse()
                .getAuthorizationCode(), getRedirectURI());


        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

        // The token endpoint
        URI tokenEndpoint = getTokenURI();

        // Make the token request
        TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

        return OIDCTokenResponseParser.parse(request.toHTTPRequest().send());
    }

    protected void clearContext(boolean clearCookie, boolean clearConsent) {
        // clear cookie and saved consent
        if (clearCookie) {
            webClient.getCookieManager().clearCookies();
        }
        if (clearConsent) {
            userConsentRepository.deleteAll();
        }
    }

    protected URI getTokenURI() {
        return UriComponentsBuilder.fromHttpUrl(TOKEN_URL)
                .port(this.port)
                .build().toUri();
    }

    protected URI getAuthorizeURI() {
        return UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
                .port(this.port)
                .build().toUri();
    }

    protected URI getRedirectURI() {
        return UriComponentsBuilder.fromHttpUrl(REDIRECT_URL)
                .build().toUri();
    }

    protected URI getIssuerURI() {
        return UriComponentsBuilder.fromHttpUrl(ISSUER_URL)
                .port(this.port)
                .build().toUri();
    }
}
