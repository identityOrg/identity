package net.prasenjit.identity;

import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.service.ClientService;
import net.prasenjit.identity.service.CodeFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Duration;
import java.time.LocalDateTime;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest
public class E2eTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private CodeFactory codeFactory;

    @Autowired
    private ClientService clientService;

    private MockMvc mockMvc;

    private AccessToken createAccessToken;

    @Before
    public void setup() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();

        UserDetails client = clientService.loadUserByUsername("client");
        createAccessToken = codeFactory.createAccessToken(client, "client", Duration.ofMinutes(1),
                "openid", LocalDateTime.now());
    }

    @Test
    public void testEncryptionDecryption() throws Exception {
        String token = createAccessToken.getAssessToken();
        mockMvc.perform(get("/api/e2e")
                .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.publicExponent", notNullValue()))
                .andExpect(jsonPath("$.modulus", notNullValue())).andReturn();
    }
}
