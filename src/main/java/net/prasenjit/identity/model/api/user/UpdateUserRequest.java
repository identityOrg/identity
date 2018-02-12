package net.prasenjit.identity.model.api.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import javax.validation.constraints.NotEmpty;

@Data
public class UpdateUserRequest {
    @JsonIgnore
    private String username;
    @NotEmpty
    private String firstName;
    @NotEmpty
    private String lastName;
}
