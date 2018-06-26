package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.AuditEvent;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.oauth.BasicAuthenticationToken;
import net.prasenjit.identity.oauth.BearerAuthenticationToken;
import net.prasenjit.identity.repository.AuditEvent1Repository;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent;
import org.springframework.security.web.authentication.switchuser.AuthenticationSwitchUserEvent;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationAuditService {

    private final AuditEvent1Repository auditRepository;

    @Transactional
    @EventListener(value = AuthenticationSuccessEvent.class)
    public void authenticationSuccessEventHandler(AuthenticationSuccessEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setPrincipleName(event.getAuthentication().getName());
        fillDetailAuditInfo(event, audit);
        auditRepository.save(audit);
        log.info("Auth success event " + audit);
    }

    @Transactional
    @EventListener(value = AuthenticationSwitchUserEvent.class)
    public void sessionFixationEventHandler(AuthenticationSwitchUserEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setPrincipleName(event.getAuthentication().getName());
        audit.setMessage("Switching to principle" + event.getTargetUser().getUsername());
        fillDetailAuditInfo(event, audit);
        auditRepository.save(audit);
        log.info("Auth success event " + audit);
    }

    @Transactional
    @EventListener(value = SessionFixationProtectionEvent.class)
    public void sessionFixationEventHandler(SessionFixationProtectionEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setPrincipleName(event.getAuthentication().getName());
        audit.setMessage("Switching from " + event.getOldSessionId() + " to " + event.getNewSessionId());
        fillDetailAuditInfo(event, audit);
        auditRepository.save(audit);
        log.info("Auth success event " + audit);
    }

    @Transactional
    @EventListener(value = AbstractAuthenticationFailureEvent.class)
    public void authenticationFailureEventHandler(AbstractAuthenticationFailureEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setExceptionName(event.getException().getClass().getSimpleName());
        audit.setExceptionMessage(event.getException().getMessage());
        audit.setPrincipleName(event.getAuthentication().getName());
        fillDetailAuditInfo(event, audit);
        auditRepository.save(audit);
        log.info("Auth success event " + audit);
    }

    private void fillDetailAuditInfo(AbstractAuthenticationEvent event, AuditEvent audit) {
        if (event.getSource() != null && event.getSource() instanceof AbstractAuthenticationToken) {
            AbstractAuthenticationToken authToken = (AbstractAuthenticationToken) event.getSource();
            if (authToken.getDetails() != null && authToken.getDetails() instanceof WebAuthenticationDetails) {
                audit.setSessionId(((WebAuthenticationDetails) authToken.getDetails()).getSessionId());
                audit.setRemoteIp(((WebAuthenticationDetails) authToken.getDetails()).getRemoteAddress());
            }
            if (authToken.getPrincipal() instanceof User) {
                audit.setPrincipleType("USER");
            } else if (authToken.getPrincipal() instanceof Client) {
                audit.setPrincipleType("CLIENT");
            }
            if (authToken instanceof BasicAuthenticationToken) {
                audit.setAuthType("BASIC");
            } else if (authToken instanceof BearerAuthenticationToken) {
                audit.setAuthType("BEARER");
            } else if (authToken instanceof UsernamePasswordAuthenticationToken) {
                audit.setAuthType("FORM");
            }
        }
    }
}
