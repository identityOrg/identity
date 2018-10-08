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

package net.prasenjit.identity.controller;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.config.doc.SwaggerDocumented;
import net.prasenjit.identity.entity.user.User;
import net.prasenjit.identity.entity.user.UserProfile;
import net.prasenjit.identity.exception.ItemNotFoundException;
import net.prasenjit.identity.model.openid.AddressClaim;
import net.prasenjit.identity.model.openid.StandardClaim;
import net.prasenjit.identity.repository.UserRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.FatalBeanException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.ClassUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.beans.PropertyDescriptor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@RestController
@SwaggerDocumented
@RequestMapping(value = "api/me")
@RequiredArgsConstructor
public class MeController implements MeApi {

    private static final String[] PROFILE_CLAIM = ("name,family_name,given_name,middle_name,nickname," +
            "preferred_username,profile,picture,website,gender,birthdate,zoneinfo,locale,updated_at").split(",");
    private static final String[] EMAIL_CLAIM = "email,email_verified".split(",");
    private static final String[] PHONE_CLAIM = "phone_number,phone_number_verified".split(",");

    private final UserRepository userRepository;

    @Override
    @GetMapping
    public StandardClaim me(Authentication authentication) {
        Optional<User> userOptional = userRepository.findById(authentication.getName());
        if (!userOptional.isPresent()) {
            throw new ItemNotFoundException("profile not found");
        }
        UserProfile userProfile = userOptional.get().getUserProfile();
        StandardClaim standardClaim = new StandardClaim();
        standardClaim.setSub(userProfile.getSub());
        standardClaim.setName(userProfile.getName());
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (authority.getAuthority().equals("profile")) {
                copyProperty(userProfile, standardClaim, PROFILE_CLAIM);
            }
            if (authority.getAuthority().equals("email")) {
                copyProperty(userProfile, standardClaim, EMAIL_CLAIM);
            }
            if (authority.getAuthority().equals("address")) {
                AddressClaim addressClaim = new AddressClaim();
                BeanUtils.copyProperties(userProfile.getAddress(), addressClaim);
                standardClaim.setAddress(addressClaim);
            }
            if (authority.getAuthority().equals("phone")) {
                copyProperty(userProfile, standardClaim, PHONE_CLAIM);
            }
        }
        return standardClaim;
    }

    private void copyProperty(UserProfile source, StandardClaim target, String[] copyProperty) {
        Class<?> actualEditable = target.getClass();
        PropertyDescriptor[] targetPds = BeanUtils.getPropertyDescriptors(actualEditable);
        List<String> propertyList = Arrays.asList(copyProperty);

        for (PropertyDescriptor targetPd : targetPds) {
            Method writeMethod = targetPd.getWriteMethod();
            if (writeMethod != null && propertyList.contains(targetPd.getName())) {
                PropertyDescriptor sourcePd = BeanUtils.getPropertyDescriptor(source.getClass(), targetPd.getName());
                if (sourcePd != null) {
                    Method readMethod = sourcePd.getReadMethod();
                    if (readMethod != null &&
                            ClassUtils.isAssignable(writeMethod.getParameterTypes()[0], readMethod.getReturnType())) {
                        try {
                            if (!Modifier.isPublic(readMethod.getDeclaringClass().getModifiers())) {
                                readMethod.setAccessible(true);
                            }
                            Object value = readMethod.invoke(source);
                            if (!Modifier.isPublic(writeMethod.getDeclaringClass().getModifiers())) {
                                writeMethod.setAccessible(true);
                            }
                            writeMethod.invoke(target, value);
                        } catch (Throwable ex) {
                            throw new FatalBeanException(
                                    "Could not copy property '" + targetPd.getName() + "' from source to target", ex);
                        }
                    }
                }
            }
        }
    }
}
