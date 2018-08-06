package net.prasenjit.identity.entity.converter;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.introspect.VisibilityChecker;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.client.URIInfoContainer;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.security.GrantType;
import net.prasenjit.identity.security.ResponseType;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;
import java.lang.reflect.ParameterizedType;

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

    @Converter
    static public class StringArrayConverter extends AbstractJsonConverter<String[]> {
    }

    @Converter
    static public class URIInfoConverter extends AbstractJsonConverter<URIInfoContainer> {
    }

    @Converter
    static public class GrantTypeArrayConverter extends AbstractJsonConverter<GrantType[]> {
    }

    @Converter
    static public class ResponseTypeArrayConverter extends AbstractJsonConverter<ResponseType[]> {
    }

    @Converter
    static public class SecurityInfoConverter extends AbstractJsonConverter<SecurityInfoConverter> {
    }
}
