package org.springframework.cloud.security.oauth2.proxy;

import java.util.HashMap;
import java.util.Map;

import org.springframework.cloud.security.oauth2.proxy.ProxyAuthenticationProperties.Route;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

/**
 * Pre-filter that adds an OAuth2 access token as a downstream authorization header if it
 * can detect the token as part of the currently authenticated principal.
 * 
 * @author Dave Syer
 *
 */
public class OAuth2TokenRelayFilter extends ZuulFilter {

	private static final String ACCESS_TOKEN = "ACCESS_TOKEN";
	private Map<String, Route> routes = new HashMap<String, Route>();

	public OAuth2TokenRelayFilter(ProxyAuthenticationProperties properties) {
		this.routes = properties.getRoutes();
	}

	@Override
	public int filterOrder() {
		return 10;
	}

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public boolean shouldFilter() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth instanceof OAuth2Authentication) {
			Object details = auth.getDetails();
			if (details instanceof OAuth2AuthenticationDetails) {
				OAuth2AuthenticationDetails oauth = (OAuth2AuthenticationDetails) details;
				RequestContext ctx = RequestContext.getCurrentContext();
				if (ctx.containsKey("proxy")) {
					String id = (String) ctx.get("proxy");
					if (routes.containsKey(id)) {
						if (!Route.Scheme.OAUTH2.matches(routes.get(id).getScheme())) {
							return false;
						}
					}
				}
				ctx.set(ACCESS_TOKEN, oauth.getTokenValue());
				return true;
			}
		}
		return false;
	}

	@Override
	public Object run() {
		RequestContext ctx = RequestContext.getCurrentContext();
		ctx.addZuulRequestHeader("authorization", "Bearer " + ctx.get(ACCESS_TOKEN));
		return null;
	}

}
