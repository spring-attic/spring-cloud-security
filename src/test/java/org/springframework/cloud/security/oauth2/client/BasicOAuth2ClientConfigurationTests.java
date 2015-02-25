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
package org.springframework.cloud.security.oauth2.client;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

import java.net.URI;
import java.util.ArrayList;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.cloud.client.loadbalancer.LoadBalancerInterceptor;
import org.springframework.cloud.client.loadbalancer.LoadBalancerRequest;
import org.springframework.cloud.security.oauth2.client.BasicOAuth2ClientConfigurationTests.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

/**
 * @author Dave Syer
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = TestConfiguration.class)
@WebAppConfiguration
@TestPropertySource(properties = {"debug=true", "spring.oauth2.client.clientId=client",
		"spring.oauth2.client.clientSecret=secret" })
public class BasicOAuth2ClientConfigurationTests {

	@Autowired
	private OAuth2RestTemplate restTemplate;

	@Test
	public void restTemplateHasLoadBalancer() throws Exception {
		assertThat(new ArrayList<Object>(restTemplate.getInterceptors()),
				hasItem(instanceOf(LoadBalancerInterceptor.class)));
	}

	@Configuration
	@EnableAutoConfiguration
	protected static class TestConfiguration {
		
		@Bean
		public LoadBalancerClient loadBalancerClient() {
			return new LoadBalancerClient() {
				
				@Override
				public URI reconstructURI(ServiceInstance instance, URI original) {
					return null;
				}
				
				@Override
				public <T> T execute(String serviceId, LoadBalancerRequest<T> request) {
					return null;
				}
				
				@Override
				public ServiceInstance choose(String serviceId) {
					return null;
				}
			};
		}

	}

}
