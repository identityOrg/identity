package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.service.OAuth2Service;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Controller
@RequestMapping("oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuth2Service oAuth2Service;

    @PostMapping(value = "token", params = "grant_type=password")
    @ResponseBody
    public OAuthToken oAuthToken(@RequestParam(value = "grant_type") String grantType,
                                 @RequestParam(value = "username") String username,
                                 @RequestParam(value = "password") String password,
                                 @RequestParam(value = "scope", defaultValue = "") String scope,
                                 Authentication clientAuth) {
        log.info("Processing grant {}", grantType);
        return oAuth2Service.processPasswordGrant((Client) clientAuth.getPrincipal(), username, password, scope);
    }

    @GetMapping("authorize")
    public String oAuthAuthorize() {
        return "authorize";
    }
}
