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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.autoconfigure.social.FacebookAutoConfiguration;
import org.springframework.boot.autoconfigure.social.SocialWebAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.test.EnvironmentTestUtils;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.cloud.security.oauth2.client.OAuth2ClientAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.social.connect.ConnectionFactoryLocator;
import org.springframework.stereotype.Component;

/**
 * @author Dave Syer
 *
 */
public class ResourceServerTokenServicesConfigurationTests {

	private ConfigurableApplicationContext context;

	private ConfigurableEnvironment environment = new StandardEnvironment();
	
	@Rule
	public ExpectedException expected = ExpectedException.none();

	@After
	public void close() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	public void defaultIsRemoteTokenServices() {
		expected.expectMessage("Field error in object 'spring.oauth2.resource'");
		context = new SpringApplicationBuilder(ResourceConfiguration.class).web(false)
				.run();
		RemoteTokenServices services = context.getBean(RemoteTokenServices.class);
		assertNotNull(services);
	}

	@Test
	public void useRemoteTokenServices() {
		EnvironmentTestUtils.addEnvironment(environment,
				"spring.oauth2.resource.tokenInfoUri:http://example.com");
		context = new SpringApplicationBuilder(ResourceConfiguration.class)
				.environment(environment).web(false).run();
		RemoteTokenServices services = context.getBean(RemoteTokenServices.class);
		assertNotNull(services);
	}

	@Test
	public void switchToUserInfo() {
		EnvironmentTestUtils.addEnvironment(environment,
				"spring.oauth2.resource.userInfoUri:http://example.com");
		context = new SpringApplicationBuilder(ResourceConfiguration.class)
				.environment(environment).web(false).run();
		UserInfoTokenServices services = context.getBean(UserInfoTokenServices.class);
		assertNotNull(services);
	}

	@Test
	public void userInfoDoesNotRequireClient() {
		EnvironmentTestUtils.addEnvironment(environment,"spring.oauth2.client.clientId:",
				"spring.oauth2.resource.userInfoUri:http://example.com");
		context = new SpringApplicationBuilder(ResourceConfiguration.class)
				.environment(environment).web(false).run();
		UserInfoTokenServices services = context.getBean(UserInfoTokenServices.class);
		assertNotNull(services);
	}

	@Test
	public void preferUserInfo() {
		EnvironmentTestUtils.addEnvironment(environment,
				"spring.oauth2.resource.userInfoUri:http://example.com",
				"spring.oauth2.resource.tokenInfoUri:http://example.com",
				"spring.oauth2.resource.preferTokenInfo:false");
		context = new SpringApplicationBuilder(ResourceConfiguration.class)
				.environment(environment).web(false).run();
		UserInfoTokenServices services = context.getBean(UserInfoTokenServices.class);
		assertNotNull(services);
	}

	@Test
	public void switchToJwt() {
		EnvironmentTestUtils.addEnvironment(environment,
				"spring.oauth2.resource.jwt.keyValue=FOOBAR");
		context = new SpringApplicationBuilder(ResourceConfiguration.class)
				.environment(environment).web(false).run();
		DefaultTokenServices services = context.getBean(DefaultTokenServices.class);
		assertNotNull(services);
	}

	@Test
	public void customizeJwt() {
		EnvironmentTestUtils.addEnvironment(environment,
				"spring.oauth2.resource.jwt.keyValue=FOOBAR");
		context = new SpringApplicationBuilder(ResourceConfiguration.class,
				JwtCustomization.class).environment(environment).web(false).run();
		JwtAccessTokenConverter services = context.getBean(JwtAccessTokenConverter.class);
		assertNotNull(services);
		assertEquals(context.getBean(JwtAccessTokenConverterConfigurer.class),
				services.getAccessTokenConverter());
	}

	@Test
	public void asymmetricJwt() {
		EnvironmentTestUtils.addEnvironment(environment,
				"spring.oauth2.resource.jwt.keyValue=" + publicKey);
		context = new SpringApplicationBuilder(ResourceConfiguration.class)
				.environment(environment).web(false).run();
		DefaultTokenServices services = context.getBean(DefaultTokenServices.class);
		assertNotNull(services);
	}

	@Test
	public void springSocialUserInfo() {
		EnvironmentTestUtils.addEnvironment(environment,
				"spring.oauth2.resource.userInfoUri:http://example.com",
				"spring.social.facebook.app-id=foo",
				"spring.social.facebook.app-secret=bar");
		context = new SpringApplicationBuilder(SocialResourceConfiguration.class)
				.environment(environment).web(true).run();
		ConnectionFactoryLocator connectionFactory = context
				.getBean(ConnectionFactoryLocator.class);
		assertNotNull(connectionFactory);
		SpringSocialTokenServices services = context
				.getBean(SpringSocialTokenServices.class);
		assertNotNull(services);
	}

	@Configuration
	@Import({ ResourceServerTokenServicesConfiguration.class,
			RefreshAutoConfiguration.class, OAuth2ClientAutoConfiguration.class,
			PropertyPlaceholderAutoConfiguration.class })
	protected static class ResourceConfiguration {
	}

	@Component
	protected static class JwtCustomization extends DefaultAccessTokenConverter implements
			JwtAccessTokenConverterConfigurer {
		@Override
		public void configure(JwtAccessTokenConverter converter) {
			converter.setAccessTokenConverter(this);
		}
	}

	@Import({ FacebookAutoConfiguration.class, SocialWebAutoConfiguration.class })
	protected static class SocialResourceConfiguration extends ResourceConfiguration {
		@Bean
		public EmbeddedServletContainerFactory embeddedServletContainerFactory() {
			return Mockito.mock(EmbeddedServletContainerFactory.class);
		}
	}

	private static String publicKey = "-----BEGIN PUBLIC KEY-----\n"
			+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnGp/Q5lh0P8nPL21oMMrt2RrkT9AW5jgYwLfSUnJVc9G6uR3cXRRDCjHqWU5WYwivcF180A6CWp/ireQFFBNowgc5XaA0kPpzEtgsA5YsNX7iSnUibB004iBTfU9hZ2Rbsc8cWqynT0RyN4TP1RYVSeVKvMQk4GT1r7JCEC+TNu1ELmbNwMQyzKjsfBXyIOCFU/E94ktvsTZUHF4Oq44DBylCDsS1k7/sfZC2G5EU7Oz0mhG8+Uz6MSEQHtoIi6mc8u64Rwi3Z3tscuWG2ShtsUFuNSAFNkY7LkLn+/hxLCu2bNISMaESa8dG22CIMuIeRLVcAmEWEWH5EEforTg+QIDAQAB\n"
			+ "-----END PUBLIC KEY-----";

}
