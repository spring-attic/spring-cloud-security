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
package org.springframework.cloud.security.oauth2.resource;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.cloud.security.oauth2.resource.OAuth2ResourceConfiguration.ResourceServerCondition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
@Configuration
@Conditional(ResourceServerCondition.class)
@ConditionalOnClass({ EnableResourceServer.class, SecurityProperties.class })
@ConditionalOnWebApplication
@EnableResourceServer
@Import(ResourceServerTokenServicesConfiguration.class)
public class OAuth2ResourceConfiguration {

	@Autowired
	private ResourceServerProperties resource;
	
	@Bean
	@ConditionalOnMissingBean(ResourceServerConfigurer.class)
	public ResourceServerConfigurer resourceServer() {
		return new ResourceSecurityConfigurer(resource);
	}

	protected static class ResourceSecurityConfigurer extends ResourceServerConfigurerAdapter {

		private ResourceServerProperties resource;

		@Autowired
		public ResourceSecurityConfigurer(ResourceServerProperties resource) {
			this.resource = resource;
		}

		@Override
		public void configure(ResourceServerSecurityConfigurer resources)
				throws Exception {
			resources.resourceId(resource.getResourceId());
		}
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest().authenticated();
		}

	}

	@Configuration
	protected static class ResourceServerOrderProcessor implements BeanPostProcessor {

		@Override
		public Object postProcessAfterInitialization(Object bean, String beanName)
				throws BeansException {
			if (bean instanceof ResourceServerConfiguration) {
				ResourceServerConfiguration configuration = (ResourceServerConfiguration) bean;
				configuration.setOrder(getOrder());
			}
			return bean;
		}

		@Override
		public Object postProcessBeforeInitialization(Object bean, String beanName)
				throws BeansException {
			return bean;
		}

		private int getOrder() {
			if (ClassUtils
					.isPresent(
							"org.springframework.boot.actuate.autoconfigure.ManagementServerProperties",
							null)) {
				return ManagementServerProperties.ACCESS_OVERRIDE_ORDER - 10;
			}
			return SecurityProperties.ACCESS_OVERRIDE_ORDER - 10;
		}

	}
	
	protected static class ResourceServerCondition extends SpringBootCondition {

		@Override
		public ConditionOutcome getMatchOutcome(ConditionContext context,
				AnnotatedTypeMetadata metadata) {
			Environment environment = context.getEnvironment();
			RelaxedPropertyResolver resolver = new RelaxedPropertyResolver(environment);
			String client = environment.resolvePlaceholders("${oauth2.client.clientId:}");
			if (StringUtils.hasText(client)) {
				return ConditionOutcome.match("found client id");
			}
			if (!resolver.getSubProperties("spring.oauth2.resource.jwt").isEmpty()) {
				return ConditionOutcome.match("found JWT resource configuration");
			}
			if (!resolver.getSubProperties("spring.oauth2.resource.userInfoUri").isEmpty()) {
				return ConditionOutcome.match("found UserInfo URI resource configuration");
			}
			return ConditionOutcome.noMatch("found neither client id nor JWT resource");
		}
		
	}
	
}
