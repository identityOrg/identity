package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.model.AsymmetricE2EResponse;
import net.prasenjit.identity.service.e2e.E2EService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "e2e")
@RequiredArgsConstructor
public class E2EController {

    private final E2EService e2EService;

    @GetMapping
    public AsymmetricE2EResponse asymmetricE2E() {
        return e2EService.getAsymmetricKey();
    }

    @PostMapping(value = "encrypt", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public String encrypt(@RequestBody String data) {
        return e2EService.encrypt(data);
    }

    @PostMapping(value = "decrypt", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public String decrypt(@RequestBody String data) {
        return e2EService.decrypt(data);
    }
}
