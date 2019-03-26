/*
 * Copyright 2015 the original author or authors.
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

package org.springframework.cloud.security.oauth2.client;

import static org.junit.Assert.assertFalse;

import java.net.URI;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * @author Dave Syer
 *
 */
public class OAuth2LoadBalancerClientAutoConfigurationTests {

	private ConfigurableApplicationContext context;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	@After
	public void close() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void clientNotConfigured() {
		this.context = new SpringApplicationBuilder(NoClientConfiguration.class)
				.properties("spring.config.name=test", "server.port=0",
						"security.oauth2.resource.userInfoUri:https://example.com")
				.run();
		assertFalse(this.context.containsBean("loadBalancedOauth2RestTemplate"));
	}

	@Test
	public void clientConfigured() throws Exception {
		this.context = new SpringApplicationBuilder(ClientConfiguration.class)
				.properties("spring.config.name=test", "server.port=0",
						"security.oauth2.resource.userInfoUri:https://example.com",
						"security.oauth2.client.clientId=foo")
				.run();
		OAuth2RestTemplate template = this.context
				.getBean("loadBalancedOauth2RestTemplate", OAuth2RestTemplate.class);
		ClientHttpRequest request = template.getRequestFactory()
				.createRequest(new URI("http://nosuchservice"), HttpMethod.GET);
		expected.expectMessage("No instances available for nosuchservice");
		request.execute();
	}

	@EnableAutoConfiguration
	@Configuration
	protected static class NoClientConfiguration {
	}

	@EnableAutoConfiguration
	@Configuration
	@EnableOAuth2Sso
	protected static class ClientConfiguration {

		@LoadBalanced
		@Bean
		public OAuth2RestTemplate loadBalancedOauth2RestTemplate(
				OAuth2ProtectedResourceDetails resource,
				OAuth2ClientContext oauth2Context) {
			return new OAuth2RestTemplate(resource, oauth2Context);
		}

	}
}
