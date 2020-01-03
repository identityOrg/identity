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

package net.prasenjit.identity.entity.converter;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.model.Profile;
import org.springframework.util.StringUtils;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.net.URI;
import java.net.URISyntaxException;

@Slf4j
public abstract class AbstractJsonConverter<T> implements AttributeConverter<T, String> {

    private ObjectMapper objectMapper;

    private AbstractJsonConverter() {
        objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        VisibilityChecker<?> visibility = objectMapper.getSerializationConfig().getDefaultVisibilityChecker()
                .withFieldVisibility(JsonAutoDetect.Visibility.ANY)
                .withGetterVisibility(JsonAutoDetect.Visibility.NONE)
                .withSetterVisibility(JsonAutoDetect.Visibility.NONE)
                .withCreatorVisibility(JsonAutoDetect.Visibility.NONE)
                .withIsGetterVisibility(JsonAutoDetect.Visibility.NONE);
        objectMapper.setVisibility(visibility);
    }

    @Override
    public String convertToDatabaseColumn(T attribute) {
        if (attribute == null) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            log.error("Failed to JSON convert user detail in JPA converter");
            throw new RuntimeException(e);
        }
    }

    @Override
    public T convertToEntityAttribute(String dbData) {
        if (dbData == null) {
            return null;
        }
        ParameterizedType parameterizedType = (ParameterizedType) getClass().getGenericSuperclass();

        @SuppressWarnings("unchecked")
        Class<T> returnType = (Class<T>) parameterizedType.getActualTypeArguments()[0];
        try {
            return objectMapper.readValue(dbData, returnType);
        } catch (IOException e) {
            log.error("Error reading JSON to object in JPA converter");
            throw new RuntimeException(e);
        }
    }

    @Converter(autoApply = true)
    static public class ProfileConverter extends AbstractJsonConverter<Profile> {
    }

    @Converter(autoApply = true)
    static public class AuthorizationRequestConverter implements AttributeConverter<AuthorizationRequest, String> {
        @Override
        public String convertToDatabaseColumn(AuthorizationRequest authorizationRequest) {
            if (authorizationRequest != null) {
                return authorizationRequest.toURI().toString();
            }
            return null;
        }

        @Override
        public AuthorizationRequest convertToEntityAttribute(String s) {
            if (StringUtils.hasText(s)) {
                try {
                    AuthorizationRequest authorizationRequest = AuthorizationRequest.parse(new URI(s));
                    if (authorizationRequest.getScope() != null && authorizationRequest.getScope().contains("openid")) {
                        authorizationRequest = AuthenticationRequest.parse(new URI(s));
                    }
                    return authorizationRequest;
                } catch (ParseException | URISyntaxException e) {
                    throw new SerializeException("Couldn't de serialize auth request: " + e.getMessage(), e);
                }
            }
            return null;
        }
    }
}
