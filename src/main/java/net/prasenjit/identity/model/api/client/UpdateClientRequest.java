package net.prasenjit.identity.model.api.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import net.prasenjit.identity.entity.Scope;
import org.springframework.format.annotation.DateTimeFormat;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.net.URL;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Set;

@Data
public class UpdateClientRequest {
    @JsonIgnore
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
    private Set<Scope> scopes;
}
