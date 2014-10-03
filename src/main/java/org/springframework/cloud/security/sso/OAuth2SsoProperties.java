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
package org.springframework.cloud.security.sso;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.security.oauth2.OAuth2ClientProperties;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
@ConfigurationProperties("oauth2.sso")
@Data
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class OAuth2SsoProperties {

	private final OAuth2ClientProperties client;

	private String serviceId = "sso";

	private String logoutPath = "/logout";

	@Value("${vcap.services.${oauth2.sso.serviceId:sso}.credentials.logoutUri:}")
	private String logoutUri;

	private String loginPath = "/login";

	private Home home = new Home();

	@Data
	public static class Home {
		private String path = "/";
		private boolean secure = true;
	}

	public String getLogoutUri(String redirectUrl) {
		return StringUtils.hasText(logoutUri) ? logoutUri : client.getTokenUri().replace("/oauth/token",
				"/logout.do?redirect=" + redirectUrl);
	}

}
