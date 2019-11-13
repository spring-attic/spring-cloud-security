/*
 * Copyright 2015-2019 the original author or authors.
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

package org.springframework.cloud.security.oauth2.client.feign;

import feign.Client;
import feign.Feign;
import feign.FeignException;
import feign.Response;
import feign.Request;
import feign.RequestLine;
import feign.Target;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

import java.io.IOException;
import java.util.Collections;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OAuth2FeignRetryerTests {

	private final Request request = Request.create(Request.HttpMethod.GET,
			"http://localhost/makeCall", Collections.emptyMap(), null);

	private Response successResponse = Response.builder().status(200).request(request)
			.build();

	private Response failureResponse = Response.builder().status(401).request(request)
			.build();

	private OAuth2ClientContext oAuth2ClientContext;

	private Client client;

	private Feign feign;

	@Before
	public void setUp() {
		this.oAuth2ClientContext = mock(OAuth2ClientContext.class);
		this.client = mock(Client.class);
		this.feign = Feign.builder().errorDecoder(new OAuth2FeignErrorDecoder())
				.retryer(new OAuth2FeignRetryer(oAuth2ClientContext))
				.requestInterceptor(new OAuth2FeignRequestInterceptor(oAuth2ClientContext,
						new BaseOAuth2ProtectedResourceDetails()))
				.client(client).build();
	}

	@Test
	public void doesNotFailWithOneException() throws IOException {
		when(oAuth2ClientContext.getAccessToken())
				.thenReturn(new MockOAuth2AccessToken("MOCKED_TOKEN"));
		when(client.execute(any(Request.class), any(Request.Options.class)))
				.thenReturn(failureResponse).thenReturn(successResponse);

		TestApi api = feign.newInstance(
				new Target.HardCodedTarget<>(TestApi.class, "http://localhost"));

		api.makeCall();

		verify(oAuth2ClientContext, times(1)).setAccessToken(isNull());
		verify(oAuth2ClientContext, times(2)).getAccessToken();
	}

	@Test
	public void failsWithMoreThenOneException() throws IOException {
		when(oAuth2ClientContext.getAccessToken())
				.thenReturn(new MockOAuth2AccessToken("MOCKED_TOKEN"));
		when(client.execute(any(Request.class), any(Request.Options.class)))
				.thenReturn(failureResponse).thenReturn(failureResponse);

		TestApi api = feign.newInstance(
				new Target.HardCodedTarget<>(TestApi.class, "http://localhost"));

		Assertions.assertThrows(FeignException.Unauthorized.class, api::makeCall);

		verify(oAuth2ClientContext, times(1)).setAccessToken(isNull());
		verify(oAuth2ClientContext, times(2)).getAccessToken();
	}

	interface TestApi {

		@RequestLine("GET /makeCall")
		void makeCall();

	}

}
