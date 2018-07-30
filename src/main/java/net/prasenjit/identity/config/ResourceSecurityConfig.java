package net.prasenjit.identity.config;

import net.prasenjit.identity.security.bearer.BearerAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@Order(90)
public class ResourceSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().antMatchers("/api/**", "/.well-known/**")
                .and().cors().and()
                .csrf().disable()
                .addFilterBefore(createBearerFilter(), BasicAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/.well-known/**", "/api/keys")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    private BearerAuthenticationFilter createBearerFilter() throws Exception {
        return new BearerAuthenticationFilter(authenticationManager);
    }
}
