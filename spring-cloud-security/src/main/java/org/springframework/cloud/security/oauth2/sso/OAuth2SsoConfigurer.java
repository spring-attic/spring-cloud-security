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

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Configurer for the request matching and access rules governing SSO resources (defaults
 * to all resources and a plain "authenticated" access rule). Beans of this type will be
 * applied to the Spring Security filter during configuration time.
 * 
 * @author Dave Syer
 *
 */
public interface OAuth2SsoConfigurer {

	/**
	 * Add request matchers (e.g. if only a subset of resources should be protected)
	 * 
	 * @param matchers a builder for request matchers
	 */
	void match(RequestMatchers matchers);

	/**
	 * Configure the access rules for the requests already matched in
	 * {@link #match(RequestMatchers)}. It's best not to use the matcher methods on the
	 * provided builder, since that will override changes made elsewhere. But you can (and
	 * should) use the matcher methods in the {@link HttpSecurity#authorizeRequests()}
	 * sub-builder to control the access rules for the matched resources.
	 * 
	 * @param http the current HttpSecurity builder
	 * @throws Exception if the HttpSecurity builder does
	 */
	void configure(HttpSecurity http) throws Exception;

	public final static class RequestMatchers extends
			AbstractRequestMatcherRegistry<RequestMatchers> {
		private List<RequestMatcher> requestMatchers = new ArrayList<RequestMatcher>();

		@Override
		protected RequestMatchers chainRequestMatchers(
				List<RequestMatcher> requestMatchers) {
			this.requestMatchers.addAll(requestMatchers);
			return this;
		}

		public RequestMatcher[] getRequestMatchers() {
			return requestMatchers.toArray(new RequestMatcher[0]);
		}
	}

}
