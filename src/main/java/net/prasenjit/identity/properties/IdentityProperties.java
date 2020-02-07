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

package net.prasenjit.identity.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Data
@Component
@ConfigurationProperties(prefix = "identity")
public class IdentityProperties {
    private CryptoProperties cryptoProperties = new CryptoProperties();
    private ServerMetadata serverMetadata = new ServerMetadata();
    private CodeProperty codeProperty = new CodeProperty();
    private Duration userPasswordValidity = Duration.ofDays(60);
    private Duration e2eKeyValidity = Duration.ofHours(6);
    private int lockUserOnErrorCount = 3;
    private int lockUserOn7DayErrorCount = 10;
    private int rememberLoginDays = 30;
    private int clientSecretLength = 32;
    private boolean detectPasswordChangeForRememberMe = true;
}
