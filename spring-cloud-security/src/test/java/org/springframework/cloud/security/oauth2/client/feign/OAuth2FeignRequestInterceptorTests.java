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