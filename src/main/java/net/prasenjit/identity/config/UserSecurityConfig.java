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
                .mvcMatchers("/security/authorize")
                .authenticated()
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
