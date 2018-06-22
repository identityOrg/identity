package net.prasenjit.identity.model.api.client;

import lombok.Data;
import net.prasenjit.identity.entity.Scope;
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
    private Set<Scope> scopes;
}
