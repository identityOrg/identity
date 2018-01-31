package net.prasenjit.identity.config;

import net.prasenjit.identity.oauth.BearerAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;

@Configuration
@Order(80)
public class ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().mvcMatchers("/oauth/token")
                .and()
                .csrf().disable()
                .authorizeRequests().anyRequest().permitAll()
                .and()
                .addFilterBefore(basicClientFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(bearerClientFilter(), BasicAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    private Filter basicClientFilter() {
        return new net.prasenjit.identity.oauth.BasicAuthenticationFilter(authenticationManager);
    }

    private Filter bearerClientFilter() {
        return new BearerAuthenticationFilter(authenticationManager);
    }
}
