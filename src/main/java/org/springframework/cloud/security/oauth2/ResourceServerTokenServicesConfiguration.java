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
package org.springframework.cloud.security.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.social.connect.support.OAuth2ConnectionFactory;

/**
 * @author Dave Syer
 *
 */
@Configuration
@EnableConfigurationProperties(ResourceServerProperties.class)
@Import(ClientConfiguration.class)
public class ResourceServerTokenServicesConfiguration {

	@Autowired
	private ResourceServerProperties resource;

	@Autowired
	private OAuth2ClientProperties client;

	@Bean
	@ConditionalOnMissingBean(ResourceServerTokenServices.class)
	@ConditionalOnExpression("${oauth2.resource.preferTokenInfo:${OAUTH2_RESOURCE_PREFERTOKENINFO:true}}")
	protected RemoteTokenServices remoteTokenServices() {
		RemoteTokenServices services = new RemoteTokenServices();
		services.setCheckTokenEndpointUrl(resource.getTokenInfoUri());
		services.setClientId(client.getClientId());
		services.setClientSecret(client.getClientSecret());
		return services;
	}

	@Configuration
	@ConditionalOnClass(OAuth2ConnectionFactory.class)
	@ConditionalOnExpression("!${oauth2.resource.preferTokenInfo:${OAUTH2_RESOURCE_PREFERTOKENINFO:true}}")
	protected static class SocialTokenServicesConfiguration {

		@Autowired
		private ResourceServerProperties sso;

		@Autowired
		private OAuth2ClientProperties client;

		@Autowired(required = false)
		private OAuth2ConnectionFactory<?> connectionFactory;

		@Bean
		@ConditionalOnBean(OAuth2ConnectionFactory.class)
		@ConditionalOnMissingBean(ResourceServerTokenServices.class)
		public SpringSocialTokenServices socialTokenServices() {
			return new SpringSocialTokenServices(connectionFactory, client.getClientId());
		}

		@Bean
		@ConditionalOnMissingBean({ OAuth2ConnectionFactory.class,
				ResourceServerTokenServices.class })
		public UserInfoTokenServices userInfoTokenServices() {
			return new UserInfoTokenServices(sso.getUserInfoUri(), client.getClientId());
		}

	}

	@Configuration
	@ConditionalOnMissingClass(name = "org.springframework.social.connect.support.OAuth2ConnectionFactory")
	@ConditionalOnExpression("!${oauth2.resource.preferTokenInfo:${OAUTH2_RESOURCE_PREFERTOKENINFO:true}}")
	protected static class UserInfoTokenServicesConfiguration {

		@Autowired
		private ResourceServerProperties sso;

		@Autowired
		private OAuth2ClientProperties client;

		@Bean
		@ConditionalOnMissingBean(ResourceServerTokenServices.class)
		public UserInfoTokenServices userInfoTokenServices() {
			return new UserInfoTokenServices(sso.getUserInfoUri(), client.getClientId());
		}

	}

}
