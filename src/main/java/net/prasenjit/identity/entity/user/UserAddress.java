package net.prasenjit.identity.entity.user;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Data
@Embeddable
public class UserAddress {
    /**
     * Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple
     * lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair
     * ("\r\n") or as a single line feed character ("\n").
     */
    @Column(name = "ADDRESS_FORMATTED")
    private String formatted;
    /**
     * Full street address component, which MAY include house number, street name, Post Office Box, and multi-line
     * extended street address information. This field MAY contain multiple lines, separated by newlines. Newlines
     * can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
     */
    @Column(name = "ADDRESS_STREET")
    private String street_address;
    /**
     * City or locality component.
     */
    @Column(name = "ADDRESS_LOCALITY")
    private String locality;
    /**
     * State, province, prefecture, or region component.
     */
    @Column(name = "ADDRESS_REGION")
    private String region;
    /**
     * Zip code or postal code component.
     */
    @Column(name = "ADDRESS_POSTAL_CODE")
    private String postal_code;
    /**
     * Country name component.
     */
    @Column(name = "ADDRESS_COUNTRY")
    private String country;
}
