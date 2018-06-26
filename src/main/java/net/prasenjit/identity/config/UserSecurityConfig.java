package net.prasenjit.identity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@Order(100)
public class UserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/login", "/webjars/**")
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
                .and()
                .logout().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
    }
}
