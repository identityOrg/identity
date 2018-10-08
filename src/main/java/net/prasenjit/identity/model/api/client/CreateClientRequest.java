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

package net.prasenjit.identity.model.api.client;

import lombok.Data;
import net.prasenjit.identity.entity.ScopeEntity;
import org.springframework.format.annotation.DateTimeFormat;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Set;

@Data
public class CreateClientRequest {
    @Pattern(regexp = "^[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)*$")
    private String clientId;
    @NotEmpty
    private String clientName;
    @NotNull
    private URL redirectUri;
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private LocalDateTime expiryDate;
    @NotNull
    private Duration accessTokenValidity;
    @NotNull
    private Duration refreshTokenValidity;
    private Set<ScopeEntity> scopes;
}
