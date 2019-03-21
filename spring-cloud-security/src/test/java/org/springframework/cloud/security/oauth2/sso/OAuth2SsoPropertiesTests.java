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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * @author Dave Syer
 *
 */
public class OAuth2SsoPropertiesTests {
	
	private OAuth2SsoProperties properties = new OAuth2SsoProperties("http://example.com");

	@Test
	public void defaultRoot() {
		assertEquals("/", properties.getHome().getRoot());
	}

	@Test
	public void customRoot() {
		properties.getHome().setPath(new String[] {"/ui/**", "/other"});
		assertEquals("/ui/", properties.getHome().getRoot());
	}

}
