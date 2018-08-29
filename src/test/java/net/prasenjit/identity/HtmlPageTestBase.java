package net.prasenjit.identity;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.util.Cookie;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import net.prasenjit.identity.entity.user.UserConsent;
import net.prasenjit.identity.repository.UserConsentRepository;
import net.prasenjit.identity.service.CodeFactory;
import net.prasenjit.identity.service.openid.MetadataService;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.htmlunit.MockMvcWebClientBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class HtmlPageTestBase {

    private static final String TOKEN_URL = "http://localhost/oauth/token";
    private static final String REDIRECT_URL = "http://localhost:4200/callback";
    private static final String AUTHORIZE_URL = "http://localhost/oauth/authorize";
    private static final String ISSUER_URL = "http://localhost";
    protected WebClient webClient;
    protected MockMvc mockMvc;
    @Autowired
    protected CodeFactory codeFactory;
    @Autowired
    protected MetadataService metadataService;
    // The client identifier provisioned by the server
    protected ClientID clientID = new ClientID("client");
    protected Secret clientSecret = new Secret("client");
    @Autowired
    private WebApplicationContext context;
    @Autowired
    private UserConsentRepository userConsentRepository;
    @LocalServerPort
    private int port;

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
                .useMockMvcForHosts("oid.prasenjit.net")
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

    protected URI followForError(URI uri) throws Exception {

        MvcResult mvcResult = mockMvc.perform(get(uri.getPath() + "?" + uri.getQuery()))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String location = mvcResult.getResponse().getHeader("Location");

        return URI.create(location);
    }

    protected void createUserConsent(String username, String approvedScope) {
        // Save consent
        UserConsent userConsent = new UserConsent();
        userConsent.setUsername(username);
        userConsent.setClientID(clientID.getValue());
        userConsent.setApprovalDate(LocalDateTime.now());
        userConsent.setScopes(approvedScope);
        userConsentRepository.save(userConsent);
    }

    protected URI loginForURI(URI startUrl, String username, String password) throws IOException, URISyntaxException {
        Page page = webClient.getPage(startUrl.toURL());
        assertTrue(page.isHtmlPage());
        HtmlPage loginPage = (HtmlPage) page;
        HtmlForm loginForm = loginPage.getFormByName("login");
        loginForm.getInputByName("username").setValueAttribute(username);
        loginForm.getInputByName("password").setValueAttribute(password);
        try {
            Page nextPage = loginForm.getButtonByName("submit").click();
        } catch (FailingHttpStatusCodeException ex) {
            assertEquals(404, ex.getStatusCode());
            return ex.getResponse().getWebRequest().getUrl().toURI();
        }
        throw new RuntimeException("Consent required");
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

    protected void setRememberLogin(String username) throws MalformedURLException {
        String cookieToken = codeFactory.createCookieToken(username, LocalDateTime.now());
        URL issuer = new URL(metadataService.findMetadata().getIssuer());
        webClient.getCookieManager()
                .addCookie(new Cookie(issuer.getAuthority(), "S_CONTEXT", cookieToken));
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
