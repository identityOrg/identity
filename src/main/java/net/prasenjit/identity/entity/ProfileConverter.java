package net.prasenjit.identity.entity;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.model.Profile;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;

@Slf4j
@Converter(autoApply = true)
public class ProfileConverter implements AttributeConverter<Profile, String> {

    private ObjectMapper objectMapper;

    public ProfileConverter() {
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
    public String convertToDatabaseColumn(Profile userDetails) {
        try {
            return objectMapper.writeValueAsString(userDetails);
        } catch (JsonProcessingException e) {
            log.error("Failed to JSON convert user detail in JPA converter");
            throw new RuntimeException(e);
        }
    }

    @Override
    public Profile convertToEntityAttribute(String s) {
        try {
            return objectMapper.readValue(s, Profile.class);
        } catch (IOException e) {
            log.error("Error reading JSON to object in JPA converter");
            throw new RuntimeException(e);
        }
    }
}
