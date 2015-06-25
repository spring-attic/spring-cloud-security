package org.springframework.cloud.security.oauth2.proxy;

import java.util.HashMap;
import java.util.Map;

import org.springframework.cloud.netflix.zuul.filters.ProxyRequestHelper;
import org.springframework.cloud.security.oauth2.proxy.ProxyAuthenticationProperties.Route;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

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
