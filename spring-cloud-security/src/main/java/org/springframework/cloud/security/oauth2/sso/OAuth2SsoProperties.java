/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
@ConfigurationProperties("spring.oauth2.sso")
@Data
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class OAuth2SsoProperties {

	public static final String DEFAULT_LOGIN_PATH = "/login";

	private final String accessTokenUri;

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
	 * Path to the login page, i.e. the one that triggers the redirect to the OAuth2
	 * Authorization Server.
	 */
	private String loginPath = DEFAULT_LOGIN_PATH;

	private Home home = new Home();

	private boolean logoutRedirect;

	/**
	 * The order of the Spring Security filter chain installed by by OAuth2 SSO. Defaults
	 * to a value that allows Actuator endpoints to retain their natural access rules (
	 * {@link ManagementServerProperties#BASIC_AUTH_ORDER}+1). If you change be less than
	 * this you will need to think about access rules for those endpoints (e.g. add them
	 * in a {@link OAuth2SsoConfigurer}. prepared to
	 */
	private Integer filterOrder;

	@Data
	public static class Home {

		/**
		 * Path to the all protected pages (including.
		 */
		private String[] path = new String[] { "/" };

		/**
		 * Specify if the home page is secured.
		 */
		private boolean secure = true;

		/**
		 * The root path (usually the first entry in {@link #getPath()}), but defaults to
		 * "/" if path not specified. If there are wildcards (e.g. "/**") they are
		 * stripped off.
		 * 
		 * @return the root path
		 */
		public String getRoot() {
			String result = path != null && path.length > 0 ? path[0] : "/";
			if (result.contains("*")) {
				result = result.substring(0, result.indexOf("*"));
				result = result.substring(0, result.lastIndexOf("/") + 1);
			}
			return result;
		}
	}

	public String getLogoutUri(String redirectUrl) {
		return StringUtils.hasText(logoutUri) ? logoutUri : accessTokenUri.replace(
				"/oauth/token", "/logout.do?redirect=" + redirectUrl);
	}

}
