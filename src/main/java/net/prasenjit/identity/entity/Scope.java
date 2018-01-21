package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Data
@Entity
@Table(name = "T_SCOPE")
public class Scope {
    @Id
    @Column(name = "SCOPE_ID", length = 10, nullable = false, unique = true)
    private String scopeId;

    @Column(name = "SCOPE_NAME", length = 50, nullable = false, unique = true)
    private String scopeName;
}
