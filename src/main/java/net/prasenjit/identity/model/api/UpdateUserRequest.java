package net.prasenjit.identity.model.api;

import lombok.Data;

@Data
public class UpdateUserRequest {
    private String username;
    private String firstName;
    private String lastName;
}
