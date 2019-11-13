/*
 * Copyright 2015-2019 the original author or authors.
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

package org.springframework.cloud.security.oauth2.client.feign;

import feign.RetryableException;
import feign.Retryer;
import org.springframework.security.oauth2.client.OAuth2ClientContext;

/**
 * Pre-defined custom Retryer. It will retry one more time in case of
 * {@link OAuth2FeignRetryableException} before re-throwing original exception. Before
 * retry it cleans up existing access token in {@link OAuth2ClientContext}. All other
 * exceptions handled by delegate {@link Retryer}.
 *
 * @author Artyom Gabeev
 */
public class OAuth2FeignRetryer implements Retryer {

	private final OAuth2ClientContext oAuth2ClientContext;

	private final Retryer delegate;

	private boolean attempted;

	/**
	 * Default constructor which uses the provided OAuth2ClientContext and NEVER_RETRY
	 * delegate.
	 * @param oAuth2ClientContext provided context
	 */
	public OAuth2FeignRetryer(OAuth2ClientContext oAuth2ClientContext) {
		this(oAuth2ClientContext, NEVER_RETRY);
	}

	/**
	 * Fully customizable constructor for changing delegate retryer.
	 * @param oAuth2ClientContext current oAuth2 Context
	 * @param delegate delegate retryer
	 */
	public OAuth2FeignRetryer(OAuth2ClientContext oAuth2ClientContext, Retryer delegate) {
		this.oAuth2ClientContext = oAuth2ClientContext;
		this.delegate = delegate;
	}

	/**
	 * Retries one time in case of {@link OAuth2FeignRetryableException}, before
	 * re-throwing original exception. All others {@link RetryableException} exceptions
	 * handled by delegate retryer.
	 * @param exception feign exception
	 */
	@Override
	public void continueOrPropagate(RetryableException exception) {
		if (exception instanceof OAuth2FeignRetryableException) {
			if (!attempted) {
				// remove existing access token
				oAuth2ClientContext.setAccessToken(null);
				attempted = true;
			}
			else {
				// extract original
				throw ((OAuth2FeignRetryableException) exception).getOriginalException();
			}
		}
		else {
			delegate.continueOrPropagate(exception);
		}
	}

	@Override
	public Retryer clone() {
		return new OAuth2FeignRetryer(oAuth2ClientContext, delegate);
	}

}
