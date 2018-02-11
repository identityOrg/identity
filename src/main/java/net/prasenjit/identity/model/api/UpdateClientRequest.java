package net.prasenjit.identity.model.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import net.prasenjit.identity.entity.Status;

import java.time.Duration;
import java.time.LocalDateTime;

@Data
public class UpdateClientRequest {
    @JsonIgnore
    private String clientId;
    private String clientName;
    private Status status;
    private String approvedScopes;
    private String redirectUri;
    private LocalDateTime expiryDate;
    private Duration accessTokenValidity;
    private Duration refreshTokenValidity;
}
