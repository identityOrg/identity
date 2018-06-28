package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.AuditEvent;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.oauth.BasicAuthenticationToken;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.AuditEventRepository;
import net.prasenjit.identity.repository.UserRepository;
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
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditEventService {

    private static final String PRINCIPLE_TYPE_USER = "USER";
    private static final String PRINCIPLE_TYPE_CLIENT = "CLIENT";
    private static final String AUTH_TYPE_BASIC = "BASIC";
    private static final String AUTH_TYPE_BEARER = "BEARER";
    private static final String AUTH_TYPE_FORM = "FORM";
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
        audit.setPrincipleName(event.getAuthentication().getName());
        audit.setFailure(false);
        fillDetailAuditInfo(event, audit);
        auditRepository.save(audit);
        log.info("Auth success event " + audit);
    }

    @Transactional
    @EventListener(value = AuthenticationSwitchUserEvent.class)
    public void accountSwitchEventHandler(AuthenticationSwitchUserEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setPrincipleName(event.getAuthentication().getName());
        audit.setMessage("Switching to principle" + event.getTargetUser().getUsername());
        audit.setFailure(false);
        fillDetailAuditInfo(event, audit);
        auditRepository.save(audit);
        log.info("Switch user event " + audit);
    }

    @Transactional
    @EventListener(value = SessionFixationProtectionEvent.class)
    public void sessionFixationEventHandler(SessionFixationProtectionEvent event) {
        AuditEvent audit = new AuditEvent();
        audit.setEventName(event.getClass().getSimpleName());
        audit.setEventTime(LocalDateTime.now());
        audit.setPrincipleName(event.getAuthentication().getName());
        audit.setMessage("Switching from " + event.getOldSessionId() + " to " + event.getNewSessionId());
        audit.setFailure(false);
        fillDetailAuditInfo(event, audit);
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
        audit.setPrincipleName(event.getAuthentication().getName());
        audit.setFailure(true);
        fillDetailAuditInfo(event, audit);
        audit = auditRepository.save(audit);
        checkErrorCount(audit);
        log.info("Auth failure event " + audit);
    }

    private void checkErrorCount(AuditEvent audit) {
        LocalDateTime last7Days = LocalDateTime.now().minusDays(7);
        List<AuditEvent> events = auditRepository.last7DaysEventforUserFormLogin(audit.getPrincipleName(), last7Days);
        int successiveErrorCount = 0;
        for (AuditEvent event : events) {
            if (event.getFailure()) {
                successiveErrorCount++;
            } else {
                break;
            }
        }
        if (successiveErrorCount >= identityProperties.getLockUserOnErrorCount()) {
            userService.lockUser(audit.getPrincipleName(), true);
        }
        long totalErrorInLast7Days = events.stream().filter(AuditEvent::getFailure).count();
        if (totalErrorInLast7Days >= identityProperties.getLockUserOn7DayErrorCount()) {
            Optional<User> user = userRepository.findById(audit.getPrincipleName());
            if (user.isPresent() && user.get().isEnabled()) {
                userService.changeStatus(user.get().getUsername(), Status.LOCKED, null);
            }
        }
    }

    private void fillDetailAuditInfo(AbstractAuthenticationEvent event, AuditEvent audit) {
        if (event.getSource() != null && event.getSource() instanceof AbstractAuthenticationToken) {
            AbstractAuthenticationToken authToken = (AbstractAuthenticationToken) event.getSource();
            if (authToken.getDetails() != null && authToken.getDetails() instanceof WebAuthenticationDetails) {
                audit.setSessionId(((WebAuthenticationDetails) authToken.getDetails()).getSessionId());
                audit.setRemoteIp(((WebAuthenticationDetails) authToken.getDetails()).getRemoteAddress());
            }
            if (authToken instanceof UsernamePasswordAuthenticationToken) {
                audit.setPrincipleType(PRINCIPLE_TYPE_USER);
                audit.setAuthType(AUTH_TYPE_FORM);
            } else if (authToken instanceof BasicAuthenticationToken) {
                audit.setPrincipleType(PRINCIPLE_TYPE_CLIENT);
                audit.setAuthType(AUTH_TYPE_BASIC);
            } else if (authToken.getPrincipal() instanceof Profile) {
                audit.setAuthType(AUTH_TYPE_BEARER);
                audit.setPrincipleType(((Profile) authToken.getPrincipal()).isClient() ? PRINCIPLE_TYPE_CLIENT
                        : PRINCIPLE_TYPE_USER);
            }
        }
    }
}
