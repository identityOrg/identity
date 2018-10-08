/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

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
