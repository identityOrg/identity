package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.model.JwksResponse;
import net.prasenjit.identity.service.openid.CryptographyService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class CryptographyController {
    private final CryptographyService cryptographyService;

    @RequestMapping(value = "api/keys", method = {RequestMethod.GET, RequestMethod.POST},
            produces = MediaType.APPLICATION_JSON_VALUE)
    public JwksResponse keys() {
        JwksResponse resp = new JwksResponse();
        resp.setKeys(cryptographyService.getLast5Keys());
        return resp;
    }
}