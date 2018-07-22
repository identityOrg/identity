package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.*;
import net.prasenjit.identity.events.AbstractModificationEvent;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.oauth.basic.BasicAuthenticationToken;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.AuditEventRepository;
import net.prasenjit.identity.repository.UserRepository;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent;
import org.springframework.security.web.authentication.switchuser.AuthenticationSwitchUserEvent;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditEventService {

    private final AuditEventRepository auditRepository;
    private final IdentityProperties identityProperties;
    private final UserService userService;
    private final UserRepository userRepository;

    @Transactional
    @EventListener(value = AuthenticationSuccessEvent.class)
    public void authenticationSuccessEventHandler(AuthenticationSuccessEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setDisplayLevel(-2);
        fillDetailAuditInfo(event.getAuthentication(), audit);
        auditRepository.save(audit);
        log.info("Auth success event " + audit);
    }

    @Transactional
    @EventListener(value = AuthenticationSwitchUserEvent.class)
    public void accountSwitchEventHandler(AuthenticationSwitchUserEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setMessage("Switching to principle" + event.getTargetUser().getUsername());
        audit.setDisplayLevel(-1);
        fillDetailAuditInfo(event.getAuthentication(), audit);
        auditRepository.save(audit);
        log.info("Switch user event " + audit);
    }

    @Transactional
    @EventListener(value = SessionFixationProtectionEvent.class)
    public void sessionFixationEventHandler(SessionFixationProtectionEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setMessage("Switching from " + event.getOldSessionId() + " to " + event.getNewSessionId());
        audit.setDisplayLevel(-1);
        fillDetailAuditInfo(event.getAuthentication(), audit);
        auditRepository.save(audit);
        log.info("Session fixation event " + audit);
    }

    @Transactional
    @EventListener(value = AbstractAuthenticationFailureEvent.class)
    public void authenticationFailureEventHandler(AbstractAuthenticationFailureEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setExceptionName(event.getException().getClass().getSimpleName());
        audit.setExceptionMessage(event.getException().getMessage());
        audit.setDisplayLevel(2);
        fillDetailAuditInfo(event.getAuthentication(), audit);
        audit = auditRepository.save(audit);
        checkErrorCount(audit);
        log.info("Auth failure event " + audit);
    }

    @Transactional
    @EventListener(value = AbstractModificationEvent.class)
    public void modificationEventHandler(AbstractModificationEvent event) {
        AuditEvent audit = event.createAudit();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        fillDetailAuditInfo(authentication, audit);
        audit = auditRepository.save(audit);
        log.info("Modification event " + audit);
    }

    private void checkErrorCount(AuditEvent audit) {
        if (audit.getAuthType() != AuthenticationType.FORM) {
            return;
        }
        LocalDateTime last7Days = LocalDateTime.now().minusDays(7);
        List<AuditEvent> events = auditRepository.last7DaysEventForUserFormLogin(audit.getPrincipleName(), last7Days);
        int successiveErrorCount = 0;
        for (AuditEvent event : events) {
            if (event.getDisplayLevel() > 1) {
                successiveErrorCount++;
            } else {
                break;
            }
        }
        if (successiveErrorCount >= identityProperties.getLockUserOnErrorCount()) {
            userService.lockUser(audit.getPrincipleName(), true);
        }
        long totalErrorInLast7Days = events.stream().filter(e -> e.getDisplayLevel() > 1).count();
        if (totalErrorInLast7Days >= identityProperties.getLockUserOn7DayErrorCount()) {
            Optional<User> user = userRepository.findById(audit.getPrincipleName());
            if (user.isPresent() && user.get().isEnabled()) {
                userService.changeStatus(user.get().getUsername(), Status.LOCKED, null);
            }
        }
    }

    private void fillDetailAuditInfo(Authentication authentication, AuditEvent audit) {
        if (StringUtils.hasText(authentication.getName())) {
            audit.setPrincipleName(authentication.getName());
        } else if (authentication.getCredentials() instanceof String) {
            audit.setPrincipleName((String) authentication.getCredentials());
        }
        if (authentication.getDetails() != null && authentication.getDetails() instanceof WebAuthenticationDetails) {
            audit.setSessionId(((WebAuthenticationDetails) authentication.getDetails()).getSessionId());
            audit.setRemoteIp(((WebAuthenticationDetails) authentication.getDetails()).getRemoteAddress());
        }
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            audit.setPrincipleType(PrincipleType.USER);
            audit.setAuthType(AuthenticationType.FORM);
        } else if (authentication instanceof BasicAuthenticationToken) {
            audit.setPrincipleType(PrincipleType.CLIENT);
            audit.setAuthType(AuthenticationType.BASIC);
        } else {
            audit.setAuthType(AuthenticationType.BEARER);
            if (authentication.getPrincipal() instanceof Profile) {
                audit.setPrincipleType(((Profile) authentication.getPrincipal()).isClient() ? PrincipleType.CLIENT
                        : PrincipleType.USER);
            }
        }
    }
}
