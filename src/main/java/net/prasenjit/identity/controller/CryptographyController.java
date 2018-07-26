package net.prasenjit.identity.controller;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.service.openid.CryptographyService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class CryptographyController {
    private final CryptographyService cryptographyService;

    @RequestMapping(value = "keys", method = {RequestMethod.GET, RequestMethod.POST},
            produces = MediaType.APPLICATION_JSON_VALUE)
    public List<RSAKey> keys() {
        return cryptographyService.getOrGenerateLast5Keys();
    }
}
