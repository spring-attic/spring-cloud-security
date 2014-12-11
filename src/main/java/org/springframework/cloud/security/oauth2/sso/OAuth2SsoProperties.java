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
package org.springframework.cloud.security.oauth2.sso;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
@ConfigurationProperties("oauth2.sso")
@Data
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class OAuth2SsoProperties {

	public static final String DEFAULT_LOGIN_PATH = "/login";

	private final OAuth2ClientProperties client;

	/**
	 * Id the single sign-on service.
	 */
	private String serviceId = "sso";

	/**
	 * Path to the logout page.
	 */
	private String logoutPath = "/logout";

	private String logoutUri;

	/**
	 * Path to the login page, i.e. the one that triggers the redirect to
	 * the OAuth2 Authorization Server.
	 */
	private String loginPath = DEFAULT_LOGIN_PATH;

	private Home home = new Home();

	private boolean logoutRedirect;

	@Data
	public static class Home {

		/**
		 * Path to the home page, i.e. the redirect on successful authentication.
		 */
		private String path = "/";

		/**
		 * Specify if the home page is secured.
		 */
		private boolean secure = true;
	}

	public String getLogoutUri(String redirectUrl) {
		return StringUtils.hasText(logoutUri) ? logoutUri : client.getTokenUri().replace(
				"/oauth/token", "/logout.do?redirect=" + redirectUrl);
	}

}
