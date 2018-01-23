package net.prasenjit.identity.config;

import com.hazelcast.config.Config;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.HeaderHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;
import org.springframework.util.CollectionUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

@Configuration
public class HazelcastSessionConfig {

	@Bean
	public HazelcastInstance hazelcastInstance() {
		Config config = new Config();
		return Hazelcast.newHazelcastInstance(config);
	}

	@Bean
	public HttpSessionIdResolver sessionIdResolver() {
		return new CompoundHttpSessionIdResolver();
	}

	public static class CompoundHttpSessionIdResolver implements HttpSessionIdResolver {
		private HttpSessionIdResolver headerHttpSessionIdResolver = new HeaderHttpSessionIdResolver("X-Session-Id");
		private HttpSessionIdResolver cookieHttpSessionIdResolver = new CookieHttpSessionIdResolver();

		@Override
		public List<String> resolveSessionIds(HttpServletRequest request) {
			List<String> sessionIds = headerHttpSessionIdResolver.resolveSessionIds(request);
			if (CollectionUtils.isEmpty(sessionIds)) {
				sessionIds = cookieHttpSessionIdResolver.resolveSessionIds(request);
			}
			return sessionIds;
		}

		@Override
		public void setSessionId(HttpServletRequest request, HttpServletResponse response, String sessionId) {
			headerHttpSessionIdResolver.setSessionId(request, response, sessionId);
			cookieHttpSessionIdResolver.setSessionId(request, response, sessionId);
		}

		@Override
		public void expireSession(HttpServletRequest request, HttpServletResponse response) {
			headerHttpSessionIdResolver.expireSession(request, response);
			cookieHttpSessionIdResolver.expireSession(request, response);
		}
	}
}
