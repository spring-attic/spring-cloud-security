/*
 * Copyright 2014-2015 the original author or authors.
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

package org.springframework.cloud.security.oauth2.client;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.client.loadbalancer.LoadBalancerInterceptor;
import org.springframework.cloud.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * @author Dave Syer
 *
 */
@Configuration
@ConditionalOnClass({ LoadBalancerInterceptor.class, OAuth2RestTemplate.class })
@ConditionalOnBean(LoadBalancerInterceptor.class)
@AutoConfigureAfter(OAuth2ClientAutoConfiguration.class)
public class OAuth2LoadBalancerClientAutoConfiguration {

    @Configuration
    @ConditionalOnBean(OAuth2ClientContext.class)
    protected static class LoadBalancedOauth2RestTemplateConfig {
        @Bean
        @LoadBalanced
        public OAuth2RestTemplate loadBalancedOauth2RestTemplate(
                LoadBalancerInterceptor loadBalancerInterceptor,
                OAuth2ClientContext oauth2ClientContext,
                OAuth2ProtectedResourceDetails details) {

            OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(details, oauth2ClientContext);
            List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>(
                    restTemplate.getInterceptors());
            interceptors.add(loadBalancerInterceptor);
            restTemplate.setInterceptors(interceptors);

            return restTemplate;
        }
    }

    @Configuration
    @ConditionalOnProperty(value = "spring.oauth2.userInfo.loadBalanced", matchIfMissing = false)
    protected static class UserInfoLoadBalancerConfig {
        @Bean
        public UserInfoRestTemplateCustomizer loadBalancedUserInfoRestTemplateCustomizer(final LoadBalancerInterceptor loadBalancerInterceptor) {
            return new UserInfoRestTemplateCustomizer() {
                @Override
                public void customize(OAuth2RestTemplate restTemplate) {
                    List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>(
                            restTemplate.getInterceptors());
                    interceptors.add(loadBalancerInterceptor);
                    restTemplate.setInterceptors(interceptors);
                }
            };
        }
    }

}
