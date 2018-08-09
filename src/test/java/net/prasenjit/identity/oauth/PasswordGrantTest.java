package net.prasenjit.identity.oauth;

import net.prasenjit.identity.HtmlPageTestBase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.Base64Utils;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


public class PasswordGrantTest extends HtmlPageTestBase {

    @Test
    public void testSuccess() throws Exception {
        String credentials = Base64Utils.encodeToString("client:client".getBytes(StandardCharsets.US_ASCII));

        mockMvc.perform(post("/oauth/token")
                .param("grant_type", "client_credentials")
                .param("scope", "openid")
                .header("Authorization", "Basic " + credentials))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(jsonPath("$.access_token", notNullValue()));
    }
}
