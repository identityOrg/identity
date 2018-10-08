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

package net.prasenjit.identity.security.crypto;

import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.crypto.impl.AesEncryptor;
import net.prasenjit.crypto.store.CryptoKeyFactory;
import net.prasenjit.identity.properties.IdentityProperties;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class CyclicEncryptorFactory {
    private final CryptoKeyFactory keyFactory;
    private final IdentityProperties identityProperties;

    public TextEncryptor createEncryptor(LocalDateTime dateTime) {
        int dayOfMonth = dateTime.getDayOfMonth();
        int cycle = dayOfMonth % 5;
        String cyclePassword = identityProperties.getCryptoProperties().getCyclePassword().get(cycle);
        SecretKey secretKey = keyFactory.getSecretKey("cycle-" + cycle, cyclePassword.toCharArray());
        return new AesEncryptor(secretKey);
    }
}
