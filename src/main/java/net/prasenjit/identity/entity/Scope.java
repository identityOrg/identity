package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;

@Data
@Entity
public class Scope {
    @Id
    private String scopeId;

    private String scopeName;
}
