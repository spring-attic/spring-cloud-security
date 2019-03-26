/*
 * Copyright 2015-2015 the original author or authors.
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

import java.net.URI;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateFactory;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;

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
	public void userInfoNotLoadBalanced() {
		this.context = new SpringApplicationBuilder(ClientConfiguration.class)
				.properties("spring.config.name=test", "server.port=0",
						"spring.cloud.gateway.enabled=false",
						"security.oauth2.resource.userInfoUri:https://example.com")
				.run();

		assertThat(
				this.context.containsBean("loadBalancedUserInfoRestTemplateCustomizer"))
						.isFalse();
		assertThat(this.context
				.containsBean("retryLoadBalancedUserInfoRestTemplateCustomizer"))
						.isFalse();
	}

	@Test
	public void userInfoLoadBalancedNoRetry() throws Exception {
		this.context = new SpringApplicationBuilder(ClientConfiguration.class)
				.properties("spring.config.name=test", "server.port=0",
						"spring.cloud.gateway.enabled=false",
						"security.oauth2.resource.userInfoUri:http://nosuchservice",
						"security.oauth2.resource.loadBalanced=true")
				.run();

		assertThat(
				this.context.containsBean("loadBalancedUserInfoRestTemplateCustomizer"))
						.isTrue();
		assertThat(this.context
				.containsBean("retryLoadBalancedUserInfoRestTemplateCustomizer"))
						.isFalse();

		OAuth2RestTemplate template = this.context
				.getBean(UserInfoRestTemplateFactory.class).getUserInfoRestTemplate();
		ClientHttpRequest request = template.getRequestFactory()
				.createRequest(new URI("http://nosuchservice"), HttpMethod.GET);
		expected.expectMessage("No instances available for nosuchservice");
		request.execute();
	}

	@EnableAutoConfiguration
	@Configuration
	@EnableOAuth2Sso
	protected static class ClientConfiguration {

	}

}
