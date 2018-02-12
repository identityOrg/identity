package net.prasenjit.identity.model.api.client;

import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDateTime;

@Data
public class CreateClientRequest {
    @Pattern(regexp = "/^[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)*$/")
    @NotNull
    private String clientId;
    @NotEmpty
    private String clientName;
    private String approvedScopes;
    @NotNull
    private URL redirectUri;
    private LocalDateTime expiryDate;
    @NotNull
    private Duration accessTokenValidity;
    @NotNull
    private Duration refreshTokenValidity;
}
