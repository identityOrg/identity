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

package net.prasenjit.identity.config.http;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import lombok.RequiredArgsConstructor;
import org.apache.http.client.cache.HttpCacheEntry;
import org.apache.http.client.cache.HttpCacheStorage;
import org.apache.http.client.cache.HttpCacheUpdateCallback;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import java.io.*;

@Component
@RequiredArgsConstructor
public class HazelcastHttpCache implements HttpCacheStorage, InitializingBean {

    private final HazelcastInstance hazelcastInstance;
    private IMap<String, byte[]> httpCache;

    @Override
    public void putEntry(String s, HttpCacheEntry httpCacheEntry) throws IOException {
        System.out.println("Cached");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(out);
        oos.writeObject(httpCacheEntry);
        httpCache.put(s, out.toByteArray());
    }

    @Override
    public HttpCacheEntry getEntry(String s) throws IOException {
        System.out.println("Retrieved");
        byte[] buf = httpCache.get(s);
        if (buf == null) return null;
        ByteArrayInputStream in = new ByteArrayInputStream(buf);
        ObjectInputStream oin = new ObjectInputStream(in);
        try {
            return (HttpCacheEntry) oin.readObject();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void removeEntry(String s) {
        httpCache.remove(s);
    }

    @Override
    public void updateEntry(String s, HttpCacheUpdateCallback httpCacheUpdateCallback) throws IOException {
        putEntry(s, httpCacheUpdateCallback.update(getEntry(s)));
    }

    @Override
    public void afterPropertiesSet() {
        httpCache = hazelcastInstance.getMap("http-cache");
    }
}
