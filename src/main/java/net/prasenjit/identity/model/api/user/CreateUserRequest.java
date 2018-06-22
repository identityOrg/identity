package net.prasenjit.identity.model.api.user;

import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.time.LocalDateTime;

@Data
public class CreateUserRequest {
    @Pattern(regexp = "^[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)*$")
    @NotNull
    private String username;
    private boolean admin;
    @NotEmpty
    private String firstName;
    @NotEmpty
    private String lastName;
    private LocalDateTime expiryDate;
}
