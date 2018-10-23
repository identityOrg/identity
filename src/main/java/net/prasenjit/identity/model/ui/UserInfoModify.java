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

package net.prasenjit.identity.model.ui;

import lombok.Data;

@Data
public class UserInfoModify {
    private UserAddress address;
    private String givenName;
    private String middleName;
    private String familyName;
    private String nickname;
    private String preferredUsername;
    private String zoneInfo;
    private String website;

    private String emailAddress;
    private String phoneNumber;


    @Data
    public static class UserAddress {
        private String streetAddress;
        private String country;
        private String locality;
        private String region;
        private String postalCode;
    }
}
