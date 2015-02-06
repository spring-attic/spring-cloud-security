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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.servlet.Filter;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.cloud.security.oauth2.resource.BasicOAuth2ResourceConfigurationTests.TestConfiguration;
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
@TestPropertySource(properties = { "debug:true", "spring.oauth2.resource.userInfoUri=http://example.com/me" })
public class BasicOAuth2ResourceConfigurationTests {

	@Autowired
	private WebApplicationContext context;

	@Autowired
	@Qualifier("springSecurityFilterChain")
	private Filter filter;

	private MockMvc mvc;

	@Before
	public void init() {
		mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(filter).build();
	}
	
	@Test
	public void oauth2ContextIsRequestScoped() {
		BeanDefinition bean = ((BeanDefinitionRegistry) context).getBeanDefinition("scopedTarget.oauth2ClientContext");
		assertEquals("request", bean.getScope());
	}

	@Test
	public void homePageIsSecure() throws Exception {
		mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andExpect(
						header().string("www-authenticate",
								Matchers.containsString("Bearer")));
	}

	@Configuration
	@EnableOAuth2Resource
	@EnableAutoConfiguration
	protected static class TestConfiguration {

	}

}
