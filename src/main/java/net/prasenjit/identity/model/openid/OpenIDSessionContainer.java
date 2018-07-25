package net.prasenjit.identity.model.openid;

import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Data
@Component
@Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
public class OpenIDSessionContainer implements Serializable{
    private boolean interactiveLoginDone;
    private boolean forceConsentApproval;
}
