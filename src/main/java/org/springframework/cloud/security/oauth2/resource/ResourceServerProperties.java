/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.cloud.security.oauth2.resource;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.util.StringUtils;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * @author Dave Syer
 *
 */
@ConfigurationProperties("oauth2.resource")
@Data
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class ResourceServerProperties implements Validator {
	
	@JsonIgnore
	private final OAuth2ClientProperties client;

	private String serviceId = "resource";

	/**
	 * Identifier of the resource.
	 */
	private String id;

	/**
	 * URI of the user endpoint.
	 */
	private String userInfoUri;

	/**
	 * URI of the token decoding endpoint.
	 */
	private String tokenInfoUri;

	/**
	 * Use the token info, can be set to false to use the user info.
	 */
	private boolean preferTokenInfo = true;
	
	private Jwt jwt = new Jwt();

	public String getResourceId() {
		return id;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return ResourceServerProperties.class.isAssignableFrom(clazz);
	}

	@Override
	public void validate(Object target, Errors errors) {
		ResourceServerProperties resource = (ResourceServerProperties) target;
		if (StringUtils.hasText(client.getClientId())) {
			if (!StringUtils.hasText(client.getClientSecret())) {
				if (!StringUtils.hasText(resource.getUserInfoUri())) {
					errors.rejectValue("userInfoUri", "missing.userInfoUri",
							"Missing userInfoUri (no client secret available)");
				}
			} else {
				if (isPreferTokenInfo() && !StringUtils.hasText(resource.getTokenInfoUri())) {
					if (StringUtils.hasText(getJwt().getKeyUri()) || StringUtils.hasText(getJwt().getKeyValue())) {
						// It's a JWT decoder
						return;
					}
					errors.rejectValue("tokenInfoUri", "missing.tokenInfoUri",
							"Missing tokenInfoUri and there is no JWT verifier key");
				}				
			}
		}
	}
	
	@Data
	public class Jwt {

		/**
		 * The verification key of the JWT token. Can either be a symmetric secret or PEM-encoded RSA
		 * public key. If the value is not available, you can set the URI instead.
		 */
		private String keyValue;

		/**
		 * The URI of the JWT token. Can be set if the value is not available and the key is public.
		 */
		private String keyUri;

		public String getKeyUri() {
			if (keyUri!=null) {
				return keyUri;
			}
			if (userInfoUri!=null && userInfoUri.endsWith("/userinfo")) {
				return userInfoUri.replace("/userinfo", "/token_key");
			}
			if (tokenInfoUri!=null && tokenInfoUri.endsWith("/check_token")) {
				return userInfoUri.replace("/check_token", "/token_key");
			}
			return null;
		}
	}

}
