/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.identity.service;

import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.ResourceType;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.user.User;
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
import net.prasenjit.identity.model.ui.UserInfoModify;
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
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Date;
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
        user.setUsername(request.getUsername());
        user.setExpiryDate(request.getExpiryDate());
        request.getUserClaims().put("sub", request.getUsername());
        UserInfo userInfo = new UserInfo(request.getUserClaims());
        userInfo.setUpdatedTime(new Date());
        user.setUserInfo(userInfo);

        CreateEvent csEvent = new CreateEvent(this, ResourceType.USER, user.getUsername());
        eventPublisher.publishEvent(csEvent);

        return userRepository.saveAndFlush(user);
    }

    @Transactional
    public User updateUser(UpdateUserRequest user) {
        Optional<User> optionalUser = userRepository.findById(user.getUsername());
        if (optionalUser.isEmpty()) {
            throw new ItemNotFoundException("User doesn't exist.");
        }
        User savedUser = optionalUser.get();
        savedUser.setExpiryDate(user.getExpiryDate());
        savedUser.setAdmin(user.getAdmin());
        user.getUserClaims().put("sub", user.getUsername());
        savedUser.getUserInfo().putAll(user.getUserClaims());
        savedUser.getUserInfo().setUpdatedTime(new Date());

        UpdateEvent csEvent = new UpdateEvent(this, ResourceType.USER, user.getUsername());
        eventPublisher.publishEvent(csEvent);

        return savedUser;
    }

    @Transactional
    public void lockUser(String username, boolean lock) {
        Optional<User> optionalUser = userRepository.findById(username);
        if (optionalUser.isEmpty()) {
            throw new ItemNotFoundException("User doesn't exist.");
        } else {
            optionalUser.get().setLocked(lock);
        }
    }

    @Transactional
    public User changeStatus(String username, Status status, String password) {
        Optional<User> optionalUser = userRepository.findById(username);
        if (optionalUser.isEmpty()) {
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
        if (optionalUser.isEmpty()) {
            throw new ItemNotFoundException("User doesn't exist.");
        } else {
            if (passwordEncoder.matches(oldPassword, optionalUser.get().getPassword())) {
                optionalUser.get().setPassword(passwordEncoder.encode(newPassword));
                Duration userPasswordValidity = identityProperties.getUserPasswordValidity();
                optionalUser.get().setPasswordExpiryDate(LocalDateTime.now().plus(userPasswordValidity));
                optionalUser.get().setLocked(false);

                ChangePasswordEvent cpEvent = new ChangePasswordEvent(this, ResourceType.USER, username);
                eventPublisher.publishEvent(cpEvent);
            } else {
                throw new InvalidRequestException("Old password didn't match");
            }
        }
        return optionalUser.get();
    }

    @Transactional
    public void modifyUser(String username, UserInfoModify userInfoModify) {
        Optional<User> optionalUser = userRepository.findById(username);
        if (optionalUser.isEmpty()) {
            throw new ItemNotFoundException("User doesn't exist.");
        } else {
            UserInfo userInfo = optionalUser.get().getUserInfo();
            userInfo.setGivenName(userInfoModify.getGivenName());
            userInfo.setMiddleName(userInfoModify.getMiddleName());
            userInfo.setFamilyName(userInfoModify.getFamilyName());
            userInfo.setNickname(userInfoModify.getNickname());
            userInfo.setPreferredUsername(userInfoModify.getPreferredUsername());
            userInfo.setName(userInfoModify.getGivenName() + " " + userInfoModify.getMiddleName() + " " + userInfoModify.getFamilyName());

            if ((StringUtils.hasText(userInfo.getEmailAddress())
                    && !userInfo.getEmailAddress().equals(userInfoModify.getEmailAddress())) ||
                    StringUtils.hasText(userInfoModify.getEmailAddress())
                            && !userInfoModify.getEmailAddress().equals(userInfo.getEmailAddress())) {
                userInfo.setEmailAddress(userInfoModify.getEmailAddress());
                userInfo.setEmailVerified(false);
            }

            if ((StringUtils.hasText(userInfo.getPhoneNumber())
                    && !userInfo.getPhoneNumber().equals(userInfoModify.getPhoneNumber())) ||
                    StringUtils.hasText(userInfoModify.getPhoneNumber())
                            && !userInfoModify.getPhoneNumber().equals(userInfo.getPhoneNumber())) {
                userInfo.setPhoneNumber(userInfoModify.getPhoneNumber());
                userInfo.setPhoneNumberVerified(false);
            }

            Address address = new Address();
            UserInfoModify.UserAddress userAddress = userInfoModify.getAddress();
            address.setStreetAddress(userAddress.getStreetAddress());
            address.setCountry(userAddress.getCountry());
            address.setLocality(userAddress.getLocality());
            address.setRegion(userAddress.getRegion());
            address.setPostalCode(userAddress.getPostalCode());
            address.setFormatted(userAddress.getStreetAddress() + "\n"
                    + userAddress.getLocality() + ", " + userAddress.getRegion() + "\n"
                    + userAddress.getCountry() + " PIN:" + userAddress.getPostalCode());

            userInfo.setAddress(address);

            UpdateEvent csEvent = new UpdateEvent(this, ResourceType.USER, username);
            eventPublisher.publishEvent(csEvent);
        }
    }
}
