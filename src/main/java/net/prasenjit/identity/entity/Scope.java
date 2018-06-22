package net.prasenjit.identity.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;
import java.io.Serializable;

@Data
@Entity
@Table(name = "T_SCOPE")
@NoArgsConstructor
@AllArgsConstructor
public class Scope implements Serializable {
    @Id
    @Column(name = "SCOPE_ID", length = 10, nullable = false, unique = true)
    @NotEmpty
    private String scopeId;

    @Column(name = "SCOPE_NAME", length = 50, nullable = false, unique = true)
    private String scopeName;
}
