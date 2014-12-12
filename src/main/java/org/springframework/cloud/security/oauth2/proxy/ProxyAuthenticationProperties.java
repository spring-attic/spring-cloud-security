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
package org.springframework.cloud.security.oauth2.proxy;

import java.util.HashMap;
import java.util.Map;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Dave Syer
 *
 */
@ConfigurationProperties("auth")
public class ProxyAuthenticationProperties {

	@Getter
	@Setter
	private Map<String, Route> routes = new HashMap<String, Route>();

	@Data
	public static class Route {
		private String id;
		private String scheme;

		public Route(String scheme) {
			this.scheme = scheme;
		}

		public static class Scheme {

			public static final Scheme OAUTH2 = new Scheme("oauth2");
			public static final Scheme PASSTHRU = new Scheme("passthru");
			public static final Scheme NONE = new Scheme("none");
			private final String value;

			private Scheme(String value) {
				this.value = value;
			}

			public boolean matches(String value) {
				return value!=null && value.equals(this.value);
			}
		}
	}

}
