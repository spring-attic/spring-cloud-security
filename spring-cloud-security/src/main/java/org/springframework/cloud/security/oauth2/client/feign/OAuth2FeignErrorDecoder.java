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

import feign.FeignException;
import feign.Response;
import feign.codec.ErrorDecoder;

import java.util.Date;

/**
 * Pre-defined custom ErrorDecoder for Feign client. In case of 401 error, this error
 * decode return {@link OAuth2FeignRetryableException}. For all other errors it delegates
 * to underlying error decoder.
 *
 * @author Artyom Gabeev
 */
public class OAuth2FeignErrorDecoder implements ErrorDecoder {

	private final ErrorDecoder delegate;

	private final Long delay;

	/**
	 * Default constructor which assumes default error decoder as delegated, with no delay
	 * between retries.
	 */
	public OAuth2FeignErrorDecoder() {
		this(new ErrorDecoder.Default(), null);
	}

	/**
	 * Fully customizable constructor for changing delegate error decoder and specified
	 * delay between reties.
	 * @param delegate delegate ErrorDecoder
	 * @param delay the delay between retries
	 */
	public OAuth2FeignErrorDecoder(ErrorDecoder delegate, Long delay) {
		this.delegate = delegate;
		this.delay = delay;
	}

	/**
	 * Extracts exception based on response code or delegates extraction. In case of 401
	 * status code exception is retryable.
	 * @param methodKey methodKey
	 * @param response response
	 * @return exception instance
	 */
	@Override
	public Exception decode(String methodKey, Response response) {
		if (response.status() == 401) {
			FeignException originalException = FeignException.errorStatus(methodKey,
					response);
			return new OAuth2FeignRetryableException(originalException,
					delay != null ? new Date(System.currentTimeMillis() + delay) : null);
		}
		return delegate.decode(methodKey, response);
	}

}
