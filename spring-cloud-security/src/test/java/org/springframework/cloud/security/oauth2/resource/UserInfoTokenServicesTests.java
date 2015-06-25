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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 *
 */
public class UserInfoTokenServicesTests {

	private UserInfoTokenServices services = new UserInfoTokenServices(
			"http://example.com", "foo");
	private BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
	private OAuth2RestOperations template = Mockito.mock(OAuth2RestOperations.class);
	private OAuth2ClientContext clientContext = Mockito.mock(OAuth2ClientContext.class);
	private Map<String, Object> map = new LinkedHashMap<String, Object>();

	@Before
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public void init() {
		resource.setClientId("foo");
		Mockito.when(
				template.getForEntity(Mockito.any(String.class), Mockito.any(Class.class)))
				.thenReturn(new ResponseEntity<Map>(map, HttpStatus.OK));
		Mockito.when(template.getAccessToken()).thenReturn(
				new DefaultOAuth2AccessToken("FOO"));
		Mockito.when(template.getResource()).thenReturn(resource);
		Mockito.when(template.getOAuth2ClientContext()).thenReturn(
				clientContext);
	}

	@Test
	public void sunnyDay() {
		services.setRestTemplate(template);
		assertEquals("unknown", services.loadAuthentication("FOO").getName());
	}

	@Test
	public void tokenType() {
		services.setRestTemplate(template);
		services.setTokenType("access_token");
		assertEquals("unknown", services.loadAuthentication("FOO").getName());
		ArgumentCaptor<OAuth2AccessToken> argument = ArgumentCaptor.forClass(OAuth2AccessToken.class);
		Mockito.verify(clientContext).setAccessToken(argument.capture());
		assertEquals("access_token", argument.getValue().getTokenType());
	}

	@Test
	public void noClientId() {
		services = new UserInfoTokenServices("http://example.com", null);
		resource.setClientId(null);
		services.setRestTemplate(template);
		assertEquals("unknown", services.loadAuthentication("FOO").getName());
	}

	@Test
	public void noAccessToken() {
		Mockito.when(template.getAccessToken()).thenThrow(
				new UserRedirectRequiredException("http://another.com", Collections
						.<String, String> emptyMap()));
		services = new UserInfoTokenServices("http://example.com", null);
		resource.setClientId(null);
		services.setRestTemplate(template);
		assertEquals("unknown", services.loadAuthentication("FOO").getName());
	}

	@Test
	public void userId() {
		map.put("userid", "spencer");
		services.setRestTemplate(template);
		assertEquals("spencer", services.loadAuthentication("FOO").getName());
	}

}
