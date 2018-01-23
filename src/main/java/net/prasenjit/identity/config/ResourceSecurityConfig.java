package net.prasenjit.identity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import net.prasenjit.identity.oauth.BearerAuthenticationFilter;

@Configuration
@Order(98)
public class ResourceSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/api/**").csrf().disable().addFilterBefore(createBearerFilter(),
				BasicAuthenticationFilter.class)
			.authorizeRequests()
			.anyRequest().permitAll();
	}

	private BearerAuthenticationFilter createBearerFilter() throws Exception {
		BearerAuthenticationFilter filter = new BearerAuthenticationFilter(authenticationManager());
		return filter;
	}
}
