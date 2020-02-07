package net.prasenjit.identity.service;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URL;

@Component
@RequiredArgsConstructor
public class RemoteResourceRetriever implements ResourceRetriever {
    @Qualifier("cachingRestTemplate")
    private final RestTemplate restTemplate;

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        ResponseEntity<String> forEntity = restTemplate.getForEntity(url.toString(), String.class);
        if (forEntity.getBody() == null) {
            throw new IOException("No content found");
        }
        if (forEntity.getHeaders().getContentType() == null) {
            throw new IOException("Content type not found");
        }
        return new Resource(forEntity.getBody(), forEntity.getHeaders().getContentType().toString());
    }
}
