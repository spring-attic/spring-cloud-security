/*
 * Copyright 2013-2014 the original author or authors.
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
package org.springframework.cloud.security.oauth2.sso;

import static org.junit.Assert.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.servlet.Filter;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.cloud.security.oauth2.proxy.ProxyAuthenticationProperties;
import org.springframework.cloud.security.oauth2.sso.BasicOAuth2SsoConfigurationTests.TestConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * @author Dave Syer
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = TestConfiguration.class)
@WebAppConfiguration
@TestPropertySource(properties = { "spring.oauth2.client.clientId=client",
		"spring.oauth2.client.clientSecret=secret",
		"spring.oauth2.client.authorizationUri=https://example.com/oauth/authorize",
		"spring.oauth2.client.tokenUri=https://example.com/oauth/token",
		"spring.oauth2.resource.jwt.keyValue=SSSSHHH" })
public class BasicOAuth2SsoConfigurationTests {

	@Autowired
	private WebApplicationContext context;

	@Autowired
	@Qualifier("springSecurityFilterChain")
	private Filter filter;
	
	@Autowired
	private ProxyAuthenticationProperties properties;

	private MockMvc mvc;

	@Before
	public void init() {
		mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(filter).build();
	}
	
	@Test
	public void fooRouteHasAuthenticationScheme() throws Exception {
		assertEquals("oauth2", properties.getRoutes().get("foo").getScheme());
	}

	@Test
	public void homePageIsSecure() throws Exception {
		mvc.perform(get("/")).andExpect(status().isFound())
				.andExpect(header().string("location", "http://localhost/login"));
	}

	@Configuration
	@EnableOAuth2Sso
	@EnableAutoConfiguration
	protected static class TestConfiguration {

	}

}
