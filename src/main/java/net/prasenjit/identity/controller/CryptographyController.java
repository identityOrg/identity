package net.prasenjit.identity.controller;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import net.minidev.json.JSONObject;
import net.prasenjit.identity.service.openid.CryptographyService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class CryptographyController {
    private final CryptographyService cryptographyService;

    @RequestMapping(value = "api/keys", method = {RequestMethod.GET, RequestMethod.POST}, produces = JWKSet.MIME_TYPE)
    public JSONObject keys() {
        JWKSet jwkSet = cryptographyService.loadJwkKeys();
        return jwkSet.toPublicJWKSet().toJSONObject();
    }
}
