package net.prasenjit.identity;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import net.prasenjit.identity.repository.UserConsentRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.htmlunit.MockMvcWebClientBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.Base64Utils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest
public class AuthorizationCodeGrantTest {
    private static final String TOKEN_URL = "http://localhost/oauth/token";
    private static final String REDIRECT_URL = "http://localhost:4200/callback";
    private static final String AUTHORIZE_URL = "http://localhost/oauth/authorize";
    @Autowired
    private WebApplicationContext context;

    private WebClient webClient;
    private MockMvc mockMvc;

    @Autowired
    private UserConsentRepository userConsentRepository;

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

    @Test
    public void testSuccess() throws Exception {
        UriComponents startUrl = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
                .queryParam("response_type", "code")
                .queryParam("client_id", "client")
                .build();
        // clear cookie and saved consent
        webClient.getCookieManager().clearCookies();
        userConsentRepository.deleteAll();

        Page page = webClient.getPage(startUrl.toString());
        assertTrue(page.isHtmlPage());
        HtmlPage loginPage = (HtmlPage) page;
        HtmlForm loginForm = loginPage.getFormByName("login");
        loginForm.getInputByName("username").setValueAttribute("admin");
        loginForm.getInputByName("password").setValueAttribute("admin");
        Page authorizePage = loginForm.getButtonByName("submit").click();
        assertTrue(authorizePage.isHtmlPage());
        HtmlPage authHtml = (HtmlPage) authorizePage;
        List<HtmlButton> validButtons = authHtml.getFormByName("auth").getButtonsByName("valid");
        for (HtmlButton b : validButtons) {
            if ("true".equals(b.getValueAttribute())) {
                try {
                    b.click();
                } catch (FailingHttpStatusCodeException ex) {
                    assertEquals(404, ex.getStatusCode());
                    URI redirectUri = ex.getResponse().getWebRequest().getUrl().toURI();
                    UriComponents uriComponents = UriComponentsBuilder.fromUri(redirectUri).build();
                    String authorizationCode = uriComponents.getQueryParams().getFirst("code");
                    assertNotNull(authorizationCode);
                    assertThat(authorizationCode.length(), greaterThan(0));

                    String credentials = Base64Utils.encodeToString("client:client".getBytes(StandardCharsets.US_ASCII));

                    mockMvc.perform(post(TOKEN_URL)
                            .param("grant_type", "authorization_code")
                            .param("code", authorizationCode)
                            .header("Authorization", "Basic " + credentials)
                            .accept(APPLICATION_JSON))
                            .andExpect(status().isOk())
                            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                            .andExpect(jsonPath("$.access_token", notNullValue()));
                    break;
                }
                fail("Redirection didn't happen");
            }
        }
    }

    @Test
    public void testSuccessWithRedirectUri() throws Exception {
        UriComponents startUrl = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
                .queryParam("response_type", "code")
                .queryParam("client_id", "client")
                .queryParam("redirect_uri", REDIRECT_URL)
                .build();
        // clear cookie and saved consent
        webClient.getCookieManager().clearCookies();
        userConsentRepository.deleteAll();

        Page page = webClient.getPage(startUrl.toString());
        assertTrue(page.isHtmlPage());
        HtmlPage loginPage = (HtmlPage) page;
        HtmlForm loginForm = loginPage.getFormByName("login");
        loginForm.getInputByName("username").setValueAttribute("admin");
        loginForm.getInputByName("password").setValueAttribute("admin");
        Page authorizePage = loginForm.getButtonByName("submit").click();
        assertTrue(authorizePage.isHtmlPage());
        HtmlPage authHtml = (HtmlPage) authorizePage;
        List<HtmlButton> validButtons = authHtml.getFormByName("auth").getButtonsByName("valid");
        for (HtmlButton b : validButtons) {
            if ("true".equals(b.getValueAttribute())) {
                try {
                    b.click();
                } catch (FailingHttpStatusCodeException ex) {
                    assertEquals(404, ex.getStatusCode());
                    URI redirectUri = ex.getResponse().getWebRequest().getUrl().toURI();
                    UriComponents uriComponents = UriComponentsBuilder.fromUri(redirectUri).build();
                    String authorizationCode = uriComponents.getQueryParams().getFirst("code");
                    assertNotNull(authorizationCode);
                    assertThat(authorizationCode.length(), greaterThan(0));
                    String returnedState = uriComponents.getQueryParams().getFirst("state");
                    assertThat(returnedState, isEmptyOrNullString());

                    String credentials = Base64Utils.encodeToString("client:client".getBytes(StandardCharsets.US_ASCII));

                    mockMvc.perform(post(TOKEN_URL)
                            .param("grant_type", "authorization_code")
                            .param("code", authorizationCode)
                            .param("redirect_uri", REDIRECT_URL)
                            .header("Authorization", "Basic " + credentials)
                            .accept(APPLICATION_JSON))
                            .andExpect(status().isOk())
                            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                            .andExpect(jsonPath("$.access_token", notNullValue()));
                    break;
                }
                fail("Redirection didn't happen");
            }
        }
    }

    @Test
    public void testSuccessWithRedirectUriAndState() throws Exception {
        String state = RandomStringUtils.randomAlphanumeric(8);
        UriComponents startUrl = UriComponentsBuilder.fromHttpUrl(AUTHORIZE_URL)
                .queryParam("response_type", "code")
                .queryParam("client_id", "client")
                .queryParam("state", state)
                .queryParam("redirect_uri", REDIRECT_URL)
                .build();
        // clear cookie and saved consent
        webClient.getCookieManager().clearCookies();
        userConsentRepository.deleteAll();

        Page page = webClient.getPage(startUrl.toString());
        assertTrue(page.isHtmlPage());
        HtmlPage loginPage = (HtmlPage) page;
        HtmlForm loginForm = loginPage.getFormByName("login");
        loginForm.getInputByName("username").setValueAttribute("admin");
        loginForm.getInputByName("password").setValueAttribute("admin");
        Page authorizePage = loginForm.getButtonByName("submit").click();
        assertTrue(authorizePage.isHtmlPage());
        HtmlPage authHtml = (HtmlPage) authorizePage;
        List<HtmlButton> validButtons = authHtml.getFormByName("auth").getButtonsByName("valid");
        for (HtmlButton b : validButtons) {
            if ("true".equals(b.getValueAttribute())) {
                try {
                    b.click();
                } catch (FailingHttpStatusCodeException ex) {
                    assertEquals(404, ex.getStatusCode());
                    URI redirectUri = ex.getResponse().getWebRequest().getUrl().toURI();
                    UriComponents uriComponents = UriComponentsBuilder.fromUri(redirectUri).build();
                    String authorizationCode = uriComponents.getQueryParams().getFirst("code");
                    assertNotNull(authorizationCode);
                    assertThat(authorizationCode.length(), greaterThan(0));
                    String returnedState = uriComponents.getQueryParams().getFirst("state");
                    assertThat(returnedState, notNullValue());
                    assertThat(returnedState, equalTo(state));
                    break;
                }
                fail("Redirection didn't happen");
            }
        }
    }
}
