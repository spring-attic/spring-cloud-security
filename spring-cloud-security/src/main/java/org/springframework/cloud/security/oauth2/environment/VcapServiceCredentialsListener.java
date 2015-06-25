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
package org.springframework.cloud.security.oauth2.environment;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.boot.context.config.ConfigFileApplicationListener;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.core.env.MapPropertySource;

/**
 * @author Dave Syer
 *
 */
public class VcapServiceCredentialsListener implements
		ApplicationListener<ApplicationEnvironmentPreparedEvent>, Ordered {

	// After VcapApplicationListener and ConfigFileApplicationListener so values here can
	// use those ones
	private int order = ConfigFileApplicationListener.DEFAULT_ORDER + 1;

	@Override
	public int getOrder() {
		return order;
	}

	@Override
	public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
		Map<String, Object> properties = new RelaxedPropertyResolver(
				event.getEnvironment()).getSubProperties("vcap.services.");
		if (properties == null || properties.isEmpty()) {
			return;
		}
		Map<String, Object> source = new HashMap<String, Object>();
		source.put("spring.oauth.sso.logoutUri",
				"${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.logoutUri:}");
		source.put("spring.oauth2.resource.id",
				"${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.id:}");
		source.put(
				"spring.oauth2.resource.userInfoUri",
				"${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.userInfoUri:"
						+ "${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.userInfoUri:}}");
		source.put(
				"spring.oauth2.resource.tokenInfoUri",
				"${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.tokenInfoUri:"
						+ "${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.tokenInfoUri:}}");
		source.put(
				"spring.oauth2.resource.jwt.keyUri",
				"${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.keyUri:"
						+ "${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.keyUri:}}");
		source.put(
				"spring.oauth2.resource.jwt.keyValue",
				"${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.keyValue:"
						+ "${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.keyValue:}}");
		source.put(
				"spring.oauth2.client.accessTokenUri",
				"${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.tokenUri:"
						+ "${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.tokenUri:}}");
		source.put(
				"spring.oauth2.client.userAuthorizationUri",
				"${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.authorizationUri:"
						+ "${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.authorizationUri:}}");
		source.put(
				"spring.oauth2.client.clientId",
				"${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.clientId:"
						+ "${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.clientId:}}");
		source.put(
				"spring.oauth2.client.clientSecret",
				"${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.clientSecret:"
						+ "${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.clientSecret:}}");
		source.put(
				"spring.oauth2.client.scope",
				"${vcap.services.${spring.oauth2.sso.serviceId:sso}.credentials.scope:"
						+ "${vcap.services.${spring.oauth2.resource.serviceId:resource}.credentials.scope:}}");
		event.getEnvironment().getPropertySources()
				.addLast(new MapPropertySource("cloudDefaultSecurityBindings", source));
	}

}
