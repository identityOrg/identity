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
