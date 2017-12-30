package net.prasenjit.identity.controller;

import net.prasenjit.identity.model.OAuthToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
@RequestMapping("oauth")
public class OAuthController {

    @PostMapping("token")
    @ResponseBody
    public OAuthToken oAuthToken(@ModelAttribute Map<String, String> params) {
        return new OAuthToken();
    }

    @GetMapping("authorize")
    public String oAuthAuthorize() {
        return "authorize";
    }
}
