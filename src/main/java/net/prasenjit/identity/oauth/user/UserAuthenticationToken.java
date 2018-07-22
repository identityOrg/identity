package net.prasenjit.identity.oauth.user;

import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;

public class UserAuthenticationToken extends UsernamePasswordAuthenticationToken {
    private static final long serialVersionUID = 2771963205868634647L;

    @Getter
    private LocalDateTime loginTime;

    @Getter
    private boolean remembered;

    public UserAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
        this.remembered = false;
    }

    public UserAuthenticationToken(Object principal, Object credentials, boolean remembered, LocalDateTime loginTime) {
        super(principal, credentials);
        this.remembered = remembered;
        this.loginTime = loginTime;
    }

    public UserAuthenticationToken(Object principal, Object credentials,
                                   Collection<? extends GrantedAuthority> authorities, LocalDateTime loginTime) {
        super(principal, credentials, authorities);
        this.loginTime = loginTime;
    }
}
