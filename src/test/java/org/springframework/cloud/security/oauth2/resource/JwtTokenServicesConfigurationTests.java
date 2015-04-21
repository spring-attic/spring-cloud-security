/*
 * Copyright 2013-2015 the original author or authors.
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

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.util.ReflectionUtils.findField;
import static org.springframework.util.ReflectionUtils.getField;
import static org.springframework.util.ReflectionUtils.makeAccessible;

import java.lang.reflect.Field;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.cloud.security.oauth2.resource.ResourceServerTokenServicesConfiguration.JwtTokenServicesConfiguration;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.client.RestTemplate;

/**
 * @author Will Tran
 *
 */
public class JwtTokenServicesConfigurationTests {

	@Test
	public void testSymmetricKeyUri() throws Exception {
		testKeyUri(symmetricTokenKeyResponse, "tokenkey");
	}

	@Test
	public void testAsymmetricKeyUri() throws Exception {
		testKeyUri(asymmetricTokenKeyResponse, asymmetricTokenKey);
	}

	public void testKeyUri(String tokenKeyResponse, String keyValue) throws Exception {
		JwtTokenServicesConfiguration config = new JwtTokenServicesConfiguration();
		String clientId = "clientId";
		String clientSecret = "clientSecret";
		String authHeaderValue = "Basic " + new String(Base64.encode((clientId + ":" + clientSecret).getBytes()));
		String keyUri = "https://example.com/token_key";

		ResourceServerProperties properties = new ResourceServerProperties(clientId, clientSecret);
		properties.getJwt().setKeyUri(keyUri);
		Field resourceServerPropertiesField = findField(JwtTokenServicesConfiguration.class, "resource");
		makeAccessible(resourceServerPropertiesField);
		ReflectionUtils.setField(resourceServerPropertiesField, config, properties);

		Field restTemplateField = findField(JwtTokenServicesConfiguration.class, "keyUriRestTemplate");
		makeAccessible(restTemplateField);
		RestTemplate restTemplate = (RestTemplate) getField(restTemplateField, config);

		MockRestServiceServer mockServer = MockRestServiceServer.createServer(restTemplate);
		mockServer
				.expect(requestTo(keyUri))
				.andExpect(method(GET))
				.andExpect(MockRestRequestMatchers.header("Authorization", authHeaderValue))
				.andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(tokenKeyResponse));

		JwtAccessTokenConverter converter = config.jwtTokenEnhancer();
		converter.afterPropertiesSet();

		mockServer.verify();
		Assert.assertEquals(keyValue, converter.getKey().get("value"));
	}

	private static String symmetricTokenKeyResponse = "{\"alg\":\"HMACSHA256\",\"value\":\"tokenkey\",\"kty\":\"MAC\",\"use\":\"sig\"}";
	private static String asymmetricTokenKeyResponse = "{\"alg\":\"SHA256withRSA\",\"value\":\"-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\\nrn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\\nfYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\\nLCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\\nkqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\\njfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\\nJwIDAQAB\\n-----END PUBLIC KEY-----\\n\",\"kty\":\"RSA\",\"use\":\"sig\",\"n\":\"ANJufZdrvYg5zG61x36pDq59nVUN73wSanA7hVCtN3ftT2Rm1ZTQqp5KSCfLMhaaVvJY51sHj+/i4lqUaM9CO32G93fE44VfOmPfexZeAwa8YDOikyTrhP7sZ6A4WUNeC4DlNnJF4zsznU7JxjCkASwpdL6XFwbRSzGkm6b9aM4vIewyclWehJxUGVFhnYEzIQ65qnr38feVP9enOVgQzpKsCJ+xpa8vZ/UrscoG3/IOQM6VnLrGYAyyCGeyU1JXQW/KlNmtA5eJry2Tp+MD6I34/QsNkCArHOfj8H9tXz/oc3/tVkkR252L/Lmp0TtIGfHpBmoITP9h+oKiW6NpyCc=\",\"e\":\"AQAB\"}";
	private static String asymmetricTokenKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\nrn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\nfYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\nLCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\nkqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\njfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\nJwIDAQAB\n-----END PUBLIC KEY-----\n";

}
