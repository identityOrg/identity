package net.prasenjit.identity.model.api.user;

import lombok.Data;

import javax.validation.constraints.NotEmpty;

@Data
public class PasswordUserRequest {
    @NotEmpty
    private String oldPassword;
    @NotEmpty
    private String newPassword;
}
