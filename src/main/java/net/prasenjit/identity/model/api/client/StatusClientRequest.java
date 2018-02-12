package net.prasenjit.identity.model.api.client;

import lombok.Data;
import net.prasenjit.identity.entity.Status;

import javax.validation.constraints.NotNull;

@Data
public class StatusClientRequest {
    @NotNull
    private Status status;
}
