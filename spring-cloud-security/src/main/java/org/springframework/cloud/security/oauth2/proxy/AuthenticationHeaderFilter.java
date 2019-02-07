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

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

import org.springframework.cloud.netflix.zuul.filters.ProxyRequestHelper;
import org.springframework.cloud.security.oauth2.proxy.ProxyAuthenticationProperties.Route;

/**
 * Pre-filter that can look for requests that are being proxied and cause the
 * authorization header not to be forwarded.
 *
 * @author Dave Syer
 *
 */
public class AuthenticationHeaderFilter extends ZuulFilter {

	private Map<String, Route> routes = new HashMap<String, Route>();

	private ProxyRequestHelper helper;

	public AuthenticationHeaderFilter(ProxyRequestHelper helper,
			ProxyAuthenticationProperties properties) {
		this.helper = helper;
		this.routes = properties.getRoutes();
	}

	@Override
	public int filterOrder() {
		return 9;
	}

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public boolean shouldFilter() {
		RequestContext ctx = RequestContext.getCurrentContext();
		if (ctx.containsKey("proxy")) {
			String id = (String) ctx.get("proxy");
			if (routes.containsKey(id)
					&& Route.Scheme.NONE.matches(routes.get(id).getScheme())) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Object run() {
		helper.addIgnoredHeaders("authorization");
		return null;
	}

}
