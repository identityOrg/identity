package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.config.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.StandardClaim;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@SwaggerDocumented
@RequestMapping(value = "api/me")
@RequiredArgsConstructor
public class MeController implements MeApi {

    private final UserRepository userRepository;

    @Override
    @GetMapping
    public StandardClaim me(Authentication authentication) {
        Optional<User> userOptional = userRepository.findById(authentication.getName());
        if (userOptional.isPresent()){
            return userOptional.get().getStandardClaim();
        }
        throw new ItemNotFoundException("profile not found");
    }
}
