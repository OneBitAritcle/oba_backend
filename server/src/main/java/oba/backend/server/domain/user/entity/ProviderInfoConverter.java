package oba.backend.server.doma.user.entity;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class ProviderInfoConverter implements AttributeConverter<ProviderInfo, String> {

    @Override
    public String convertToDatabaseColumn(ProviderInfo attribute) {
        return attribute == null ? null : attribute.name();
    }

    @Override
    public ProviderInfo convertToEntityAttribute(String dbData) {
        return dbData == null ? null : ProviderInfo.valueOf(dbData);
    }
}
