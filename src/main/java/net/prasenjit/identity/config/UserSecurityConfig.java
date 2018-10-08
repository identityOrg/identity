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
import net.prasenjit.identity.security.JWTRememberMe;
import net.prasenjit.identity.security.user.UserAuthenticationFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;

@Configuration
@Order(100)
@RequiredArgsConstructor
public class UserSecurityConfig extends WebSecurityConfigurerAdapter {

    private final AuthenticationHandler authenticationHandler;

    private final AuthenticationManager authenticationManager;
    private final JWTRememberMe jwtRememberMe;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/login", "/webjars/**", "/swagger-resources/**")
                .permitAll()
                .mvcMatchers("/oauth/authorize", "/oauth/connect")
                .permitAll()
                .antMatchers("/*.png", "/*.ico", "/*.xml", "/*.svg", "/*.webmanifest")
                .permitAll()
                .anyRequest()
                .hasAuthority("ADMIN")
                .and()
                .addFilterBefore(createUserFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                .authenticationEntryPoint(authenticationHandler)
                .and()
                .logout()
                .addLogoutHandler(jwtRememberMe)
                .and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and()
                .rememberMe()
                .rememberMeServices(jwtRememberMe);
    }

    private Filter createUserFilter() {
        UserAuthenticationFilter filter = new UserAuthenticationFilter(new AntPathRequestMatcher("/login", "POST"));
        filter.setAuthenticationFailureHandler(authenticationHandler);
        filter.setAuthenticationSuccessHandler(authenticationHandler);
        filter.setAuthenticationManager(authenticationManager);
        filter.setRememberMeServices(jwtRememberMe);
        return filter;
    }

}
