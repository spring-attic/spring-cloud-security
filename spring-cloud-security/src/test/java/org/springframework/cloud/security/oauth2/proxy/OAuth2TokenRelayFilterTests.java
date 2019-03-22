/*
 * Copyright 2014-2015 the original author or authors.
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

package org.springframework.cloud.security.oauth2.proxy;

import com.netflix.zuul.context.RequestContext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * @author Dave Syer
 *
 */
public class OAuth2TokenRelayFilterTests {

	private ProxyAuthenticationProperties properties = new ProxyAuthenticationProperties();

	private OAuth2TokenRelayFilter filter = new OAuth2TokenRelayFilter(properties);

	private OAuth2Authentication auth;

	private MockHttpServletRequest httpRequest = new MockHttpServletRequest();

	@Before
	public void init() {
		Authentication user = new UsernamePasswordAuthenticationToken("user", "password");
		AuthorizationRequest authorizationRequest = new AuthorizationRequest();
		authorizationRequest.setClientId("client");
		OAuth2Request request = authorizationRequest.createOAuth2Request();
		auth = new OAuth2Authentication(request, user);
		httpRequest.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, "bearer");
		httpRequest.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "FOO");
		auth.setDetails(new OAuth2AuthenticationDetails(httpRequest));
	}

	@After
	public void after() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void emptyContextNoFilter() {
		assertThat(RequestContext.getCurrentContext()).isNotNull();
		assertThat(filter.shouldFilter()).isFalse();
	}

	@Test
	public void securityContextTriggersFilter() {
		assertThat(RequestContext.getCurrentContext()).isNotNull();
		SecurityContextHolder.getContext().setAuthentication(auth);
		assertThat(filter.shouldFilter()).isTrue();
	}

	@Test
	public void tokenRelayedWithoutRestTemplate() {
		assertThat(RequestContext.getCurrentContext()).isNotNull();
		SecurityContextHolder.getContext().setAuthentication(auth);
		assertThat(filter.shouldFilter()).isTrue();
		assertThat(RequestContext.getCurrentContext().get("ACCESS_TOKEN"))
				.isEqualTo("FOO");
		filter.run();
		assertThat(RequestContext.getCurrentContext().getZuulRequestHeaders()
				.get("authorization")).isNotNull();
	}

	@Test
	public void tokenRelayedWithRestTemplate() {
		OAuth2RestOperations restTemplate = Mockito.mock(OAuth2RestOperations.class);
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId("client");
		Mockito.when(restTemplate.getResource()).thenReturn(resource);
		Mockito.when(restTemplate.getAccessToken())
				.thenReturn(new DefaultOAuth2AccessToken("BAR"));
		filter.setRestTemplate(restTemplate);
		assertThat(RequestContext.getCurrentContext()).isNotNull();
		SecurityContextHolder.getContext().setAuthentication(auth);
		assertThat(filter.shouldFilter()).isTrue();
		assertThat(RequestContext.getCurrentContext().get("ACCESS_TOKEN"))
				.isEqualTo("FOO");
		filter.run();
		assertThat(RequestContext.getCurrentContext().getZuulRequestHeaders()
				.get("authorization")).isEqualTo("bearer BAR");
	}

	@Test
	public void unauthorizedWithRestTemplate() {
		OAuth2RestOperations restTemplate = Mockito.mock(OAuth2RestOperations.class);
		AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();
		resource.setClientId("client");
		Mockito.when(restTemplate.getResource()).thenReturn(resource);
		Mockito.when(restTemplate.getAccessToken()).thenThrow(new RuntimeException());
		filter.setRestTemplate(restTemplate);
		assertThat(RequestContext.getCurrentContext()).isNotNull();
		SecurityContextHolder.getContext().setAuthentication(auth);
		assertThat(filter.shouldFilter()).isTrue();
		try {
			filter.run();
			fail("Expected BadCredentialsException");
		}
		catch (BadCredentialsException e) {
			assertThat(RequestContext.getCurrentContext().get("error.status_code"))
					.isEqualTo(401);

		}
	}

}
