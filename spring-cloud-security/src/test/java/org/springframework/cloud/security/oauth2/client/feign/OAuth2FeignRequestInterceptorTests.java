/*
 * Copyright 2015 the original author or authors.
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

package org.springframework.cloud.security.oauth2.client.feign;

import feign.RequestTemplate;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.Map;

import static org.hamcrest.Matchers.contains;

/**
 * @author João Pedro Evangelista
 */
public class OAuth2FeignRequestInterceptorTests {

    private OAuth2FeignRequestInterceptor oAuth2FeignRequestInterceptor;

    private RequestTemplate requestTemplate;

    @Before
    public void setUp() throws Exception {
        oAuth2FeignRequestInterceptor = new OAuth2FeignRequestInterceptor(new MockOAuth2ClientContext("Fancy"));
        requestTemplate = new RequestTemplate().method("GET");
    }

    @Test
    public void applyAuthorizationHeader() throws Exception {
        oAuth2FeignRequestInterceptor.apply(requestTemplate);
        System.out.println(requestTemplate);
        Map<String, Collection<String>> headers = requestTemplate.headers();
        Assert.assertTrue("RequestTemplate must have a Authorization header", headers.containsKey("Authorization"));
        Assert.assertThat("Authorization must have a value of Fancy", headers.get("Authorization"), contains("Bearer Fancy"));
    }
}