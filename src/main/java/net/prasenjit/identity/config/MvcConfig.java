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

import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.events.AbstractModificationEvent;
import net.prasenjit.identity.events.CreateEvent;
import net.prasenjit.identity.events.UpdateEvent;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.web.servlet.config.annotation.CorsRegistration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.LinkedList;
import java.util.List;

@Configuration
public class MvcConfig implements WebMvcConfigurer {

    private List<CorsRegistration> corsConfigurations = new LinkedList<>();

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login").setViewName("login");
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        CorsRegistration apiCors = registry.addMapping("/api/**")
                .allowCredentials(true)
                .allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH")
                .allowedOrigins("*")
                .maxAge(3600);
        corsConfigurations.add(apiCors);
        CorsRegistration wellKnownCors = registry.addMapping("/.well-known/**")
                .allowCredentials(true)
                .allowedMethods("GET")
                .allowedOrigins("*")
                .maxAge(3600);
        corsConfigurations.add(wellKnownCors);
    }

    @EventListener(value = AbstractModificationEvent.class)
    public void clientUpdateCorsHandler(AbstractModificationEvent event) {
        if (event instanceof CreateEvent || event instanceof UpdateEvent) {
            if (event.getSource() instanceof Client) {
                Client client = (Client) event.getSource();
                client.getMetadata().getRedirectionURIs()
                        .stream()
                        .map(UriComponentsBuilder::fromUri)
                        .map(ucb -> ucb.replacePath("").userInfo(null)
                                .query(null).fragment(null).build().toString())
                        .forEach(origin -> corsConfigurations.forEach(config -> config.allowedOrigins(origin)));
            }
        }
    }
}
