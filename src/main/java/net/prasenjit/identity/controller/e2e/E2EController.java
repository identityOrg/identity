/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.identity.controller.e2e;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.config.doc.SwaggerDocumented;
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
