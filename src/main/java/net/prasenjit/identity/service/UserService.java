package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.events.ChangePasswordEvent;
import net.prasenjit.identity.events.ChangeStatusEvent;
import net.prasenjit.identity.events.CreateEvent;
import net.prasenjit.identity.events.UpdateEvent;
import net.prasenjit.identity.exception.ConflictException;
import net.prasenjit.identity.exception.InvalidRequestException;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.exception.OperationIgnoredException;
import net.prasenjit.identity.model.api.user.CreateUserRequest;
import net.prasenjit.identity.model.api.user.UpdateUserRequest;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final IdentityProperties identityProperties;
    private final ApplicationEventPublisher eventPublisher;
    private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findById(s);
        if (user.isPresent()) {
            return user.get();
        } else {
            throw new UsernameNotFoundException("user not found");
        }
    }

    @Transactional
    public User createUser(CreateUserRequest request) {
        Optional<User> optionalUser = userRepository.findById(request.getUsername());
        if (optionalUser.isPresent()) {
            throw new ConflictException("User already exist.");
        }
        User user = new User();
        user.setActive(false);
        user.setLocked(false);
        LocalDateTime now = LocalDateTime.now();
        user.setPasswordExpiryDate(now.plus(identityProperties.getUserPasswordValidity()));
        user.setCreationDate(now);
        user.setAdmin(request.isAdmin());
        user.setPassword(RandomStringUtils.randomAlphanumeric(20)); // unknown password to create disabled user
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setExpiryDate(request.getExpiryDate());

        CreateEvent csEvent = new CreateEvent(this, ResourceType.USER, user.getUsername());
        eventPublisher.publishEvent(csEvent);

        return userRepository.saveAndFlush(user);
    }

    @Transactional
    public User updateUser(UpdateUserRequest user) {
        Optional<User> optionalUser = userRepository.findById(user.getUsername());
        if (!optionalUser.isPresent()) {
            throw new ItemNotFoundException("User doesn't exist.");
        }
        User savedUser = optionalUser.get();
        savedUser.setFirstName(user.getFirstName());
        savedUser.setLastName(user.getLastName());
        savedUser.setExpiryDate(user.getExpiryDate());
        savedUser.setAdmin(user.getAdmin());

        UpdateEvent csEvent = new UpdateEvent(this, ResourceType.USER, user.getUsername());
        eventPublisher.publishEvent(csEvent);

        return savedUser;
    }

    @Transactional
    public void lockUser(String username, boolean lock) {
        Optional<User> optionalUser = userRepository.findById(username);
        if (!optionalUser.isPresent()) {
            throw new ItemNotFoundException("User doesn't exist.");
        } else {
            optionalUser.get().setLocked(lock);
        }
    }

    @Transactional
    public User changeStatus(String username, Status status, String password) {
        Optional<User> optionalUser = userRepository.findById(username);
        if (!optionalUser.isPresent()) {
            throw new ItemNotFoundException("User doesn't exist.");
        } else if (optionalUser.get().isEnabled() == (status == Status.ACTIVE)) {
            throw new OperationIgnoredException("Status not changed");
        } else {
            optionalUser.get().setActive(status == Status.ACTIVE);
            if (status == Status.ACTIVE) {
                Assert.notNull(password, "Password is required to activate user.");
                optionalUser.get().setPassword(passwordEncoder.encode(password));

                ChangeStatusEvent csEvent = new ChangeStatusEvent(this, ResourceType.USER, username, status);
                eventPublisher.publishEvent(csEvent);
            }
        }
        return optionalUser.get();
    }

    @Transactional
    public User changePassword(String username, String oldPassword, String newPassword) {
        Optional<User> optionalUser = userRepository.findById(username);
        if (!optionalUser.isPresent()) {
            throw new ItemNotFoundException("User doesn't exist.");
        } else {
            if (passwordEncoder.matches(oldPassword, optionalUser.get().getPassword())) {
                optionalUser.get().setPassword(passwordEncoder.encode(newPassword));

                ChangePasswordEvent cpEvent = new ChangePasswordEvent(this, ResourceType.USER, username);
                eventPublisher.publishEvent(cpEvent);
            } else {
                throw new InvalidRequestException("Old password doesnt match");
            }
        }
        return optionalUser.get();
    }
}
