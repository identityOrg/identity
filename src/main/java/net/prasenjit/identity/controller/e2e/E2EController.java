package net.prasenjit.identity.controller.e2e;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.doc.SwaggerDocumented;
import net.prasenjit.identity.service.e2e.E2EService;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@SwaggerDocumented
@RequestMapping(value = "api/e2e")
@RequiredArgsConstructor
public class E2EController implements E2EApi {

    private final E2EService e2EService;

    /*
     * (non-Javadoc)
     *
     * @see net.prasenjit.identity.controller.e2e.E2EApi#asymmetricE2E()
     */
    @Override
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public RSAKey asymmetricE2E(Authentication authentication) {
        return e2EService.getAsymmetricKey(authentication);
    }

    /*
     * (non-Javadoc)
     *
     * @see net.prasenjit.identity.controller.e2e.E2EApi#encrypt(java.lang.String)
     */
    @Override
    @PostMapping(value = "encrypt", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public String encrypt(@RequestBody String data, Authentication authentication) {
        return e2EService.encrypt(authentication, data);
    }

    /*
     * (non-Javadoc)
     *
     * @see net.prasenjit.identity.controller.e2e.E2EApi#decrypt(java.lang.String)
     */
    @Override
    @PostMapping(value = "decrypt", consumes = MediaType.TEXT_PLAIN_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public String decrypt(@RequestBody String data, Authentication authentication) {
        return e2EService.decrypt(authentication, data);
    }
}
