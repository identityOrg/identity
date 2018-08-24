package net.prasenjit.identity.oauth;

import net.prasenjit.identity.HtmlPageTestBase;
import net.prasenjit.identity.model.OAuthToken;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertNotNull;


public class ClientCredentialTestTests extends HtmlPageTestBase {

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
        map.add("scope", "scope1");
        map.add("grant_type", "client_credentials");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<OAuthToken> tokenResponseEntity = restTemplate.postForEntity("/oauth/token",
                request, OAuthToken.class);
        assertNotNull(tokenResponseEntity.getBody());
        assertNotNull(tokenResponseEntity.getBody().getAccessToken());
    }

}
