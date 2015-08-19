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

import org.springframework.boot.SpringApplication;
import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.boot.context.config.ConfigFileEnvironmentPostProcessor;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * @author Dave Syer
 *
 */
public class VcapServiceCredentialsEnvironmentPostProcessor implements
EnvironmentPostProcessor, Ordered {

	// After VcapEnvironmentPostProcessor and ConfigFileEnvironmentPostProcessor so values here can
	// use those ones
	private int order = ConfigFileEnvironmentPostProcessor.DEFAULT_ORDER + 1;

	@Override
	public int getOrder() {
		return this.order;
	}

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment,
			SpringApplication application) {
		Map<String, Object> properties = new RelaxedPropertyResolver(
				environment).getSubProperties("vcap.services.");
		if (properties == null || properties.isEmpty()) {
			return;
		}
		Map<String, Object> source = new HashMap<String, Object>();
		source.put("security.oauth2.sso.logoutUri",
				"${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.logoutUri:}");
		source.put("security.oauth2.resource.id",
				"${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.id:}");
		source.put(
				"security.oauth2.resource.userInfoUri",
				"${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.userInfoUri:"
						+ "${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.userInfoUri:}}");
		source.put(
				"security.oauth2.resource.tokenInfoUri",
				"${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.tokenInfoUri:"
						+ "${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.tokenInfoUri:}}");
		source.put(
				"security.oauth2.resource.jwt.keyUri",
				"${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.keyUri:"
						+ "${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.keyUri:}}");
		source.put(
				"security.oauth2.resource.jwt.keyValue",
				"${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.keyValue:"
						+ "${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.keyValue:}}");
		source.put(
				"security.oauth2.client.accessTokenUri",
				"${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.tokenUri:"
						+ "${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.tokenUri:}}");
		source.put(
				"security.oauth2.client.userAuthorizationUri",
				"${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.authorizationUri:"
						+ "${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.authorizationUri:}}");
		source.put(
				"security.oauth2.client.clientId",
				"${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.clientId:"
						+ "${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.clientId:}}");
		source.put(
				"security.oauth2.client.clientSecret",
				"${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.clientSecret:"
						+ "${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.clientSecret:}}");
		source.put(
				"security.oauth2.client.scope",
				"${vcap.services.${security.oauth2.sso.serviceId:sso}.credentials.scope:"
						+ "${vcap.services.${security.oauth2.resource.serviceId:resource}.credentials.scope:}}");
		environment.getPropertySources()
		.addLast(new MapPropertySource("cloudDefaultSecurityBindings", source));
	}

}
