package net.prasenjit.identity.config;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.oauth.JWTRememberMe;
import net.prasenjit.identity.oauth.user.UserAuthenticationFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;

import static net.prasenjit.identity.properties.ApplicationConstants.LOGIN_TIME;
import static net.prasenjit.identity.properties.ApplicationConstants.PREVIOUS_URL;

@Configuration
@Order(100)
@RequiredArgsConstructor
public class UserSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final AuthenticationHandler HANDLER = new AuthenticationHandler();

    private final AuthenticationManager authenticationManager;
    private final JWTRememberMe jwtRememberMe;

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
                .addFilterBefore(createUserFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                .authenticationEntryPoint(HANDLER)
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
        filter.setAuthenticationFailureHandler(HANDLER);
        filter.setAuthenticationSuccessHandler(HANDLER);
        filter.setAuthenticationManager(authenticationManager);
        filter.setRememberMeServices(jwtRememberMe);
        return filter;
    }

    private static class AuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler,
            AuthenticationEntryPoint {

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
            request.getSession().setAttribute(LOGIN_TIME, LocalDateTime.now());
            if (requestURI != null) {
                response.sendRedirect(requestURI);
            } else {
                response.sendRedirect("/");
            }
        }

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response,
                             AuthenticationException authException) throws IOException, ServletException {
            UriComponentsBuilder builder = ServletUriComponentsBuilder.fromRequest(request);
            request.getSession().setAttribute(PREVIOUS_URL, builder.build().toString());
            response.sendRedirect("/login");
        }
    }
}
