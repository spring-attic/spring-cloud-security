/*
 *        Copyright 2015 the original author or authors.
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
package org.springframework.cloud.security.oauth2.client.feign;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;

/**
 * Pre-defined custom RequestInterceptor for Feign Requests
 * It uses the {@link OAuth2ClientContext OAuth2ClientContext} provided from the environment
 * and construct a new header on the request before it is made by Feign
 *
 * @author Joao Pedro Evangelista
 */
public class OAuth2FeignRequestInterceptor implements RequestInterceptor {

    public static final String BEARER = "Bearer";

    public static final String AUTHORIZATION = "Authorization";

    private final Logger logger = LoggerFactory.getLogger(OAuth2FeignRequestInterceptor.class);

    private final OAuth2ClientContext oAuth2ClientContext;

    private final String tokenType;

    private final String header;

    /**
     * Default constructor which uses the provided OAuth2ClientContext and
     * Bearer tokens within Authorization header
     *
     * @param oAuth2ClientContext provided context
     */
    public OAuth2FeignRequestInterceptor(OAuth2ClientContext oAuth2ClientContext) {
        this(oAuth2ClientContext, BEARER, AUTHORIZATION);
        logger.debug("Constructing default OAuth2FeignRequestInterceptor");
    }

    /**
     * Fully customizable constructor for changing token type and header name, in cases of Bearer and Authorization is not the default
     * such as "bearer", "authorization"
     *
     * @param oAuth2ClientContext current oAuth2 Context
     * @param tokenType           type of token e.g. "token", "Bearer"
     * @param header              name of the header e.g. "Authorization", "authorization"
     */
    public OAuth2FeignRequestInterceptor(OAuth2ClientContext oAuth2ClientContext, String tokenType, String header) {
        this.oAuth2ClientContext = oAuth2ClientContext;
        this.tokenType = tokenType;
        this.header = header;
    }

    private static boolean tokenExists(OAuth2ClientContext oAuth2ClientContext) {
        return oAuth2ClientContext.getAccessTokenRequest().getExistingToken() != null;
    }

    /**
     * Create a template with the header of provided name and extracted value
     *
     * @see RequestInterceptor#apply(RequestTemplate)
     */
    @Override
    public void apply(RequestTemplate template) {
        if (tokenExists(oAuth2ClientContext)) {
            logger.debug("Applying RequestInterceptor customization");
            template.header(header, value(tokenType));
        }
    }

    /**
     * Extracts the token value id the access token exists or returning an empty value if there is no one on the context
     * it may occasionally causes Unauthorized response since the token value is empty
     *
     * @param tokenType type name of token
     * @return extracted value from context if it exists otherwise empty String
     */
    protected String value(String tokenType) {
        final AccessTokenRequest accessTokenRequest = oAuth2ClientContext.getAccessTokenRequest();
        if (accessTokenRequest.getExistingToken() != null) {
            logger.debug("Returning token {} value", tokenType);
            return String.format("%s %s", tokenType, accessTokenRequest.getExistingToken().toString());
        }
        logger.debug("No accessTokenRequest found for Feign RequestTemplate!");
        return "";
    }


}
