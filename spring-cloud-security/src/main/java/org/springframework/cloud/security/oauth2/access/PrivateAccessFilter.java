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

package org.springframework.cloud.security.oauth2.access;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pre-filter that blocks / allow endpoints without / with an Authorization header
 *
 * @author Kevin Van Houtte
 */
public class PrivateAccessFilter extends ZuulFilter {

    private Map<String, SecureAccessLevelProperties.Route> routes = new LinkedHashMap<>();

    public PrivateAccessFilter(SecureAccessLevelProperties properties) {
        this.routes = properties.getRoutes();
    }

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        if (StringUtils.isEmpty(request.getServletPath()) || !request.getServletPath().contains("/")) {
            return false;
        }
        String key = getKey(request.getServletPath().split("/"));
        SecureAccessLevelProperties.Route accessLevel = routes.get(key);
        return accessLevel != null && "private".equals(accessLevel.getAccess());
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String header = request.getHeader("Authorization");
        if (StringUtils.isEmpty(header) || !header.startsWith("Bearer")) {
            setFailedRequest("Forbidden", 403);
        }
        return null;
    }

    private String getKey(String[] parts) {
        return parts[1];
    }

    private void setFailedRequest(String body, int code) {
        RequestContext ctx = RequestContext.getCurrentContext();
        ctx.setResponseStatusCode(code);
        if (ctx.getResponseBody() == null) {
            ctx.setResponseBody(body);
            ctx.setSendZuulResponse(false);
            throw new AccessDeniedException("Code: " + code + ", " + body); //optional
        }
    }
}
