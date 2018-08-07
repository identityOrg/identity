package net.prasenjit.identity.oauth;

import net.prasenjit.identity.model.OAuthToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ClientCredentialTestTests {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void clientCredentialGrant() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String cred = "client:client";
        String encoded = Base64Utils.encodeToString(cred.getBytes(StandardCharsets.US_ASCII));
        headers.add("Authorization", "Basic " + encoded);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("scope", "openid");
        map.add("grant_type", "client_credentials");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<OAuthToken> tokenResponseEntity = restTemplate.postForEntity("/security/token",
                request, OAuthToken.class);
        System.out.println(tokenResponseEntity.getBody());
    }

}
