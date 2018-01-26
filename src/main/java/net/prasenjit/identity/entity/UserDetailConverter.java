package net.prasenjit.identity.entity;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;

@Slf4j
@Converter(autoApply = true)
public class UserDetailConverter implements AttributeConverter<UserDetails, String> {

    private ObjectMapper objectMapper;

    public UserDetailConverter() {
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
    public String convertToDatabaseColumn(UserDetails userDetails) {
        StringBuilder builder;
        if (userDetails instanceof User) {
            builder = new StringBuilder("USER|");
        } else if (userDetails instanceof Client) {
            builder = new StringBuilder("CLIENT|");
        } else {
            throw new RuntimeException("Invalid source class for UserDetail JPA converter");
        }
        try {
            builder.append(objectMapper.writeValueAsString(userDetails));
            return builder.toString();
        } catch (JsonProcessingException e) {
            log.error("Failed to JSON convert user detail in JPA converter");
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserDetails convertToEntityAttribute(String s) {
        String jsonString;
        try {
            if (s.startsWith("USER")) {
                jsonString = s.substring(5);
                return objectMapper.readValue(jsonString, User.class);
            } else if (s.startsWith("CLIENT")) {
                jsonString = s.substring(7);
                return objectMapper.readValue(jsonString, Client.class);
            } else {
                throw new RuntimeException("Invalid serialized object in JPA converter");
            }
        } catch (IOException e) {
            log.error("Error reading JSON to object in JPA converter");
            throw new RuntimeException(e);
        }
    }
}
