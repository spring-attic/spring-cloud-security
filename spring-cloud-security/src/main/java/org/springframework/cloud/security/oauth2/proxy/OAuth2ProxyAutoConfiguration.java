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
package org.springframework.cloud.security.oauth2.proxy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.zuul.filters.ProxyRequestHelper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

import com.netflix.zuul.ZuulFilter;

/**
 * @author Dave Syer
 *
 */
@Configuration
@ConditionalOnClass({ ZuulFilter.class, EnableOAuth2Client.class,
		SecurityProperties.class })
@ConditionalOnWebApplication
@EnableConfigurationProperties(ProxyAuthenticationProperties.class)
public class OAuth2ProxyAutoConfiguration {

	@Autowired
	private ProxyAuthenticationProperties properties;

	// Inject the @Primary one because it knows how to refresh an expired token
	@Autowired(required = false)
	private OAuth2RestOperations restTemplate;

	@Autowired(required = false)
	@LoadBalanced
	private OAuth2RestOperations loadBalancedRestTemplate;

	@Bean
	public OAuth2TokenRelayFilter oauth2TokenRelayFilter() {
		OAuth2TokenRelayFilter filter = new OAuth2TokenRelayFilter(this.properties);
		if (this.loadBalancedRestTemplate != null && this.properties.isLoadBalanced()) {
			filter.setRestTemplate(this.loadBalancedRestTemplate);
		}
		else if (this.restTemplate != null) {
			filter.setRestTemplate(this.restTemplate);
		}
		return filter;
	}

	@ConditionalOnClass({ ProxyRequestHelper.class })
	@Configuration
	protected static class AuthenticationHeaderFilterConfiguration {

		@Bean
		public AuthenticationHeaderFilter authenticationHeaderFilter(
				ProxyAuthenticationProperties properties) {
			ProxyRequestHelper helper = new ProxyRequestHelper();
			return new AuthenticationHeaderFilter(helper, properties);
		}

	}

}
