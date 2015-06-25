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

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnNotWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.security.oauth2.sso.OAuth2SsoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

@Configuration
@ConditionalOnClass(OAuth2ClientContext.class)
@ConditionalOnExpression("'${spring.oauth2.client.clientId:}'!=''")
@EnableConfigurationProperties
public class OAuth2ClientAutoConfiguration {

	@Configuration
	protected static class OAuth2RestTemplateConfiguration {

		@Bean
		@Primary
		public OAuth2RestTemplate oauth2RestTemplate(
				OAuth2ClientContext oauth2ClientContext,
				OAuth2ProtectedResourceDetails details) {
			OAuth2RestTemplate template = new OAuth2RestTemplate(details, oauth2ClientContext);
			return template;
		}

		@Bean
		public OAuth2RestTemplate oauth2ClientCredentialsRestTemplate(
				OAuth2ClientContext oauth2ClientContext,
				@Qualifier("oauth2ClientCredentialsRemoteResource") OAuth2ProtectedResourceDetails details) {
			OAuth2RestTemplate template = new OAuth2RestTemplate(details, oauth2ClientContext);
			return template;
		}
	}

	@Configuration
	@EnableOAuth2Client
	protected abstract static class BaseConfiguration {

		@Resource
		@Qualifier("accessTokenRequest")
		protected AccessTokenRequest accessTokenRequest;

		@Bean
		@ConfigurationProperties("spring.oauth2.client")
		@Primary
		public AuthorizationCodeResourceDetails oauth2RemoteResource() {
			AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
			return details;
		}

		@Bean
		@ConfigurationProperties("spring.oauth2.client")
		public AuthorizationCodeResourceDetails oauth2ClientCredentialsRemoteResource() {
			AuthorizationCodeResourceDetails details = new ClientCredentialsResourceDetails();
			return details;
		}

		@Bean
		public FilterRegistrationBean oauth2ClientFilterRegistration(
				OAuth2ClientContextFilter filter) {
			FilterRegistrationBean registration = new FilterRegistrationBean();
			registration.setFilter(filter);
			registration.setOrder(-100);
			return registration;
		}

	}

	@Configuration
	@ConditionalOnNotWebApplication
	protected static class SingletonScopedConfiguration {

		@Bean
		@ConfigurationProperties("spring.oauth2.client")
		@Primary
		public ClientCredentialsResourceDetails oauth2RemoteResource() {
			ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();
			return details;
		}

		@Bean
		public OAuth2ClientContext oauth2ClientContext() {
			return new DefaultOAuth2ClientContext(new DefaultAccessTokenRequest());
		}

	}

	@Configuration
	@ConditionalOnBean(OAuth2SsoConfiguration.class)
	@ConditionalOnWebApplication
	protected static class SessionScopedConfiguration extends BaseConfiguration {

		@Bean
		@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
		public OAuth2ClientContext oauth2ClientContext() {
			return new DefaultOAuth2ClientContext(accessTokenRequest);
		}

	}

	@Configuration
	@ConditionalOnMissingBean(OAuth2SsoConfiguration.class)
	@ConditionalOnWebApplication
	protected static class RequestScopedConfiguration extends BaseConfiguration {

		@Bean
		@Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
		public OAuth2ClientContext oauth2ClientContext() {
			DefaultOAuth2ClientContext context = new DefaultOAuth2ClientContext(
					accessTokenRequest);
			Authentication principal = SecurityContextHolder.getContext()
					.getAuthentication();
			if (principal instanceof OAuth2Authentication) {
				OAuth2Authentication authentication = (OAuth2Authentication) principal;
				Object details = authentication.getDetails();
				if (details instanceof OAuth2AuthenticationDetails) {
					OAuth2AuthenticationDetails oauthsDetails = (OAuth2AuthenticationDetails) details;
					String token = oauthsDetails.getTokenValue();
					context.setAccessToken(new DefaultOAuth2AccessToken(token));
				}
			}
			return context;
		}

	}

}
