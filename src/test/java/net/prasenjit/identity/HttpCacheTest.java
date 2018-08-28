package net.prasenjit.identity;

import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import net.prasenjit.identity.config.HttpClientConfig;
import net.prasenjit.identity.config.http.HazelcastHttpCache;
import org.junit.Test;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

public class HttpCacheTest {

    @Test
    public void cacheTest() {
        RestTemplate restTemplate = getTemplate();
        LocalDateTime startTime = LocalDateTime.now();
        restTemplate.getForObject("https://www.prasenjit.net/", String.class);
        LocalDateTime endTime = LocalDateTime.now();
        long diff = ChronoUnit.MILLIS.between(startTime, endTime);
        startTime = endTime;
        System.err.println(diff);
        restTemplate.getForObject("https://www.prasenjit.net/", String.class);
        endTime = LocalDateTime.now();
        diff = ChronoUnit.MILLIS.between(startTime, endTime);
        startTime = endTime;
        System.err.println(diff);
        restTemplate.getForObject("https://www.prasenjit.net/", String.class);
        endTime = LocalDateTime.now();
        diff = ChronoUnit.MILLIS.between(startTime, endTime);
        startTime = endTime;
        System.err.println(diff);
        restTemplate.getForObject("https://www.prasenjit.net/", String.class);
        endTime = LocalDateTime.now();
        diff = ChronoUnit.MILLIS.between(startTime, endTime);
        startTime = endTime;
        System.err.println(diff);
        restTemplate.getForObject("https://www.prasenjit.net/", String.class);
        endTime = LocalDateTime.now();
        diff = ChronoUnit.MILLIS.between(startTime, endTime);
        System.err.println(diff);
    }

    private RestTemplate getTemplate() {
        HazelcastInstance hi = Hazelcast.newHazelcastInstance();
        HazelcastHttpCache hhc = new HazelcastHttpCache(hi);
        hhc.afterPropertiesSet();
        HttpClientConfig hcc = new HttpClientConfig(hhc);
        return hcc.cachingRestTemplate(hcc.cachingHttpClient());
    }
}
