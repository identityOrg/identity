package net.prasenjit.identity.model.api.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import net.prasenjit.identity.entity.Status;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDateTime;

@Data
public class UpdateClientRequest {
    @JsonIgnore
    private String clientId;
    @NotEmpty
    private String clientName;
    @NotNull
    private Status status;
    private String approvedScopes;
    @NotNull
    private URL redirectUri;
    private LocalDateTime expiryDate;
    @NotNull
    private Duration accessTokenValidity;
    @NotNull
    private Duration refreshTokenValidity;
}
