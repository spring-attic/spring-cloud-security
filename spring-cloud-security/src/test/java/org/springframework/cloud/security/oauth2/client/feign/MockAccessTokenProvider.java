package org.springframework.cloud.security.oauth2.client.feign;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

/**
 * Mocks the access token provider
 *
 * @author Mihhail Verhovtsov
 */
public class MockAccessTokenProvider implements AccessTokenProvider {

    private OAuth2AccessToken token;

    public MockAccessTokenProvider(OAuth2AccessToken token) {
        this.token = token;
    }

    @Override
    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails oAuth2ProtectedResourceDetails, AccessTokenRequest accessTokenRequest) throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException {
        return token;
    }

    @Override
    public boolean supportsResource(OAuth2ProtectedResourceDetails oAuth2ProtectedResourceDetails) {
        return true;
    }

    @Override
    public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails oAuth2ProtectedResourceDetails, OAuth2RefreshToken oAuth2RefreshToken, AccessTokenRequest accessTokenRequest) throws UserRedirectRequiredException {
        return null;
    }

    @Override
    public boolean supportsRefresh(OAuth2ProtectedResourceDetails oAuth2ProtectedResourceDetails) {
        return false;
    }

}
