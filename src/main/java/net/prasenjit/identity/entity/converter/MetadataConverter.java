package net.prasenjit.identity.entity.converter;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.springframework.util.StringUtils;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter
public class MetadataConverter implements AttributeConverter<OIDCClientMetadata, String> {
    @Override
    public String convertToDatabaseColumn(OIDCClientMetadata attribute) {
        if (attribute != null) {
            return attribute.toString();
        }
        return null;
    }

    @Override
    public OIDCClientMetadata convertToEntityAttribute(String dbData) {
        if (StringUtils.hasText(dbData)) {
            try {
                return OIDCClientMetadata.parse(JSONObjectUtils.parse(dbData));
            } catch (ParseException e) {
                throw new RuntimeException("Failed to convert metadata column to object");
            }
        }
        return null;
    }
}
