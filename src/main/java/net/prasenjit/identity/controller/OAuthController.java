package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.service.OAuth2Service;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Controller
@RequestMapping("oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final OAuth2Service oAuth2Service;

    @PostMapping(value = "token", params = "grant_type=password")
    @ResponseBody
    public OAuthToken passwordGrantToken(
            @RequestParam(value = "username") String username,
            @RequestParam(value = "password") String password,
            @RequestParam(value = "scope", defaultValue = "") String scope,
            Authentication clientAuth) {
        log.info("Processing password grant");
        return oAuth2Service.processPasswordGrant((Client) clientAuth.getPrincipal(), username, password, scope);
    }

    @PostMapping(value = "token", params = "grant_type=client_credentials")
    @ResponseBody
    public OAuthToken clientCredentialGrantToken(
            @RequestParam(value = "scope", defaultValue = "") String scope,
            Authentication clientAuth) {
        log.info("Processing password grant");
        return oAuth2Service.processClientCredentialsGrant((Client) clientAuth.getPrincipal(), scope);
    }

    @GetMapping("authorize")
    public String oAuthAuthorize(@RequestParam("response_type") String responseType,
                                 @RequestParam("client_id") String clientId,
                                 @RequestParam(value = "redirect_uri", required = false) String redirectUri,
                                 @RequestParam(value = "scope", defaultValue = "") String scope,
                                 @RequestParam(value = "state", required = false) String state,
                                 Authentication authentication, Model model) {
        AuthorizationModel authorizationModel = oAuth2Service.validateAuthorizationGrant(responseType,
                (User) authentication.getPrincipal(), clientId, scope, state, redirectUri);
        if (authorizationModel.isValid()) {
            model.addAttribute("model", authorizationModel);
            return "authorize";
        } else {
            return "redirect:/error";
        }
    }

    @PostMapping("authorize")
    public String submitAuthorize(@ModelAttribute AuthorizationModel model){
        System.out.println(model);
        return "authorize";
    }
}
