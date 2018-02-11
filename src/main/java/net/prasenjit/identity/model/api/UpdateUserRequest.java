package net.prasenjit.identity.model.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

@Data
public class UpdateUserRequest {
    @JsonIgnore
    private String username;
    private String firstName;
    private String lastName;
}
