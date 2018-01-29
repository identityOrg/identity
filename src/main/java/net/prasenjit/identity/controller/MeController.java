package net.prasenjit.identity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import net.prasenjit.identity.doc.SwaggerDocumented;

@RestController
@SwaggerDocumented
@RequestMapping(value = "api/me")
public class MeController implements MeApi {

	@Override
	@GetMapping
	public UserDetails me(Authentication authentication) {
		return (UserDetails) authentication.getPrincipal();
	}
}
