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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.boot.test.EnvironmentTestUtils;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;

/**
 * @author Dave Syer
 *
 */
public class VcapServiceCredentialsListenerTests {

	private VcapServiceCredentialsListener listener = new VcapServiceCredentialsListener();

	private ConfigurableEnvironment environment = new StandardEnvironment();

	@Test
	public void noop() {
		listener.onApplicationEvent(new ApplicationEnvironmentPreparedEvent(
				new SpringApplication(), null, environment));
		Map<String, Object> properties = new RelaxedPropertyResolver(environment)
				.getSubProperties("spring.oauth2");
		assertTrue(properties == null || properties.isEmpty());
	}

	@Test
	public void addTokenUri() {
		EnvironmentTestUtils.addEnvironment(environment, "vcap.services.sso.credentials.tokenUri:http://example.com");
		listener.onApplicationEvent(new ApplicationEnvironmentPreparedEvent(
				new SpringApplication(), null, environment));
		assertEquals("http://example.com", environment.resolvePlaceholders("${spring.oauth2.client.accessTokenUri}"));
	}

	@Test
	public void addUserInfoUri() {
		EnvironmentTestUtils.addEnvironment(environment, "vcap.services.sso.credentials.userInfoUri:http://example.com");
		listener.onApplicationEvent(new ApplicationEnvironmentPreparedEvent(
				new SpringApplication(), null, environment));
		assertEquals("http://example.com", environment.resolvePlaceholders("${spring.oauth2.resource.userInfoUri}"));
	}

}
