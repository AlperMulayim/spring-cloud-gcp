/*
 *  Copyright 2017 original author or authors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.springframework.data.spanner.core.mapping;

import org.springframework.data.mapping.context.AbstractMappingContext;
import org.springframework.data.mapping.model.FieldNamingStrategy;
import org.springframework.data.mapping.model.Property;
import org.springframework.data.mapping.model.PropertyNameFieldNamingStrategy;
import org.springframework.data.mapping.model.SimpleTypeHolder;
import org.springframework.data.util.TypeInformation;

/**
 * A mapping context that provides ways to create persie
 *
 * @author Ray Tsang
 * @author Chengyuan Zhao
 */
public class SpannerMappingContext extends
		AbstractMappingContext<SpannerPersistentEntity<?>, SpannerPersistentProperty> {

	private static final FieldNamingStrategy DEFAULT_NAMING_STRATEGY = PropertyNameFieldNamingStrategy.INSTANCE;

	private FieldNamingStrategy fieldNamingStrategy = DEFAULT_NAMING_STRATEGY;

	public SpannerMappingContext() {

	}

	public void setFieldNamingStrategy(FieldNamingStrategy fieldNamingStrategy) {
		this.fieldNamingStrategy = fieldNamingStrategy == null ? DEFAULT_NAMING_STRATEGY
				: fieldNamingStrategy;
	}

	@Override
	protected <T> SpannerPersistentEntity<T> createPersistentEntity(
			TypeInformation<T> typeInformation) {
		BasicSpannerPersistentEntity<T> entity = new BasicSpannerPersistentEntity<T>(
				typeInformation);

		return entity;
	}

	@Override
	protected SpannerPersistentProperty createPersistentProperty(Property property,
			SpannerPersistentEntity<?> owner, SimpleTypeHolder simpleTypeHolder) {
		return new BasicSpannerPersistentProperty(property, owner, simpleTypeHolder,
				this.fieldNamingStrategy);
	}
}
