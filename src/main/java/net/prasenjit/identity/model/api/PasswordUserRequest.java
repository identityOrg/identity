package net.prasenjit.identity.model.api;

import lombok.Data;

@Data
public class PasswordUserRequest {
    private String oldPassword;
    private String newPassword;
}
