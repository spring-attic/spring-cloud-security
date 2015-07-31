package org.springframework.cloud.security.oauth2.client.feign;

import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.HashMap;

/**
 * Mocks the current client context
 *
 * @author João Pedro Evangelista
 */
final class MockOAuth2ClientContext implements OAuth2ClientContext {

    private final String value;

    public MockOAuth2ClientContext(String value) {
        this.value = value;
    }

    @Override
    public OAuth2AccessToken getAccessToken() {
        return new DefaultOAuth2AccessToken(value);
    }

    @Override
    public void setAccessToken(OAuth2AccessToken accessToken) {

    }

    @Override
    public AccessTokenRequest getAccessTokenRequest() {
        DefaultAccessTokenRequest tokenRequest = new DefaultAccessTokenRequest(new HashMap<String, String[]>());
        tokenRequest.setExistingToken(new DefaultOAuth2AccessToken(value));
        return tokenRequest;
    }

    @Override
    public void setPreservedState(String stateKey, Object preservedState) {

    }

    @Override
    public Object removePreservedState(String stateKey) {
        return null;
    }
}
