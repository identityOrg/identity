package net.prasenjit.identity.e2e;

import net.prasenjit.identity.HtmlPageTestBase;
import net.prasenjit.identity.entity.AccessTokenEntity;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.service.ClientService;
import net.prasenjit.identity.service.CodeFactory;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;
import java.time.LocalDateTime;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


public class E2eTest extends HtmlPageTestBase {

    @Autowired
    private CodeFactory codeFactory;

    @Autowired
    private ClientService clientService;


    @Test
    public void testEncryptionDecryption() throws Exception {

        UserDetails client = clientService.loadUserByUsername("client");
        AccessTokenEntity createAccessToken = codeFactory.createAccessToken(Profile.create(client), "client", Duration.ofMinutes(1),
                "openid", LocalDateTime.now());

        String token = createAccessToken.getAssessToken();
        mockMvc.perform(get("/api/e2e")
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.publicExponent", notNullValue()))
                .andExpect(jsonPath("$.modulus", notNullValue())).andReturn();
    }
}
