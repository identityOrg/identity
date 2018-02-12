package net.prasenjit.identity.model.api.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import net.prasenjit.identity.entity.Status;

import javax.validation.constraints.NotNull;

@Data
public class StatusUserRequest {
    @NotNull
    private Status status;
    private String password;
}
