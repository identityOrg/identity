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
