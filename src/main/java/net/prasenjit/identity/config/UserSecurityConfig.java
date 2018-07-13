package net.prasenjit.identity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@Order(100)
public class UserSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final AuthenticationHandler HANDLER = new AuthenticationHandler();

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/login", "/webjars/**", "/swagger-resources/**", "/.well-known/**")
                .permitAll()
                .mvcMatchers("/oauth/authorize")
                .authenticated()
                .antMatchers("/*.png", "/*.ico", "/*.xml", "/*.svg", "/*.webmanifest")
                .permitAll()
                .anyRequest()
                .hasAuthority("ADMIN")
                .and()
                .formLogin()
                .loginPage("/login")
                .failureHandler(HANDLER)
                .successHandler(HANDLER)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(HANDLER)
                .and()
                .logout().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
    }

    private static class AuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler,
            AuthenticationEntryPoint {
        private static final String PREVIOUS_URL = AuthenticationHandler.class.getName() + ".PREVIOUS_URL";

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException exception) throws IOException, ServletException {
            if (exception instanceof CredentialsExpiredException) {
                response.sendRedirect("/changePassword");
            } else {
                response.sendRedirect("/login?error");
            }
        }

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authentication) throws IOException, ServletException {
            String requestURI = (String) request.getSession().getAttribute(PREVIOUS_URL);
            if (requestURI != null) {
                response.sendRedirect(requestURI);
            } else {
                response.sendRedirect("/");
            }
        }

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                             AuthenticationException authException) throws IOException, ServletException {
            UriComponentsBuilder builder = ServletUriComponentsBuilder.fromCurrentRequest();
            request.getSession().setAttribute(PREVIOUS_URL, builder.build().toString());
            response.sendRedirect("/login");
        }
    }
}
