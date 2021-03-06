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

package net.prasenjit.identity.config;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.properties.IdentityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.HeaderHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;
import org.springframework.util.CollectionUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

@Configuration
@EnableJdbcHttpSession
@RequiredArgsConstructor
public class SessionConfig implements SessionRepositoryCustomizer<JdbcIndexedSessionRepository> {

    private final IdentityProperties identityProperties;

    @Bean
    public HttpSessionIdResolver sessionIdResolver() {
        return new CompoundHttpSessionIdResolver();
    }

    @Override
    public void customize(JdbcIndexedSessionRepository sessionRepository) {
        sessionRepository.setTableName(identityProperties.getSessionProperties().getTableName());
        sessionRepository.setDefaultMaxInactiveInterval(identityProperties.getSessionProperties().getMaxInactiveInterval());
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
