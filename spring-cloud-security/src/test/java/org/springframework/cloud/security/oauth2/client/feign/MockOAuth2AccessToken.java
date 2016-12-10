package org.springframework.cloud.security.oauth2.client.feign;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * Mocks the OAuth2 access token
 *
 * @author Mihhail Verhovtsov
 */
public class MockOAuth2AccessToken implements OAuth2AccessToken {

        private String value;

        public MockOAuth2AccessToken(String value) {
            this.value = value;
        }

        @Override
        public Map<String, Object> getAdditionalInformation() {
            return null;
        }

        @Override
        public Set<String> getScope() {
            return null;
        }

        @Override
        public OAuth2RefreshToken getRefreshToken() {
            return null;
        }

        @Override
        public String getTokenType() {
            return null;
        }

        @Override
        public boolean isExpired() {
            return false;
        }

        @Override
        public Date getExpiration() {
            return null;
        }

        @Override
        public int getExpiresIn() {
            return 0;
        }

        @Override
        public String getValue() {
            return value;
        }
    }