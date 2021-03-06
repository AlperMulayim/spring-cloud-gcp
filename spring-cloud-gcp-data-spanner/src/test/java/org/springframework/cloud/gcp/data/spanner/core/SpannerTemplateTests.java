/*
 *  Copyright 2018 original author or authors.
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

package org.springframework.cloud.gcp.data.spanner.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import com.google.cloud.spanner.DatabaseClient;
import com.google.cloud.spanner.Key;
import com.google.cloud.spanner.KeySet;
import com.google.cloud.spanner.Mutation;
import com.google.cloud.spanner.Options.QueryOption;
import com.google.cloud.spanner.Options.ReadOption;
import com.google.cloud.spanner.ReadContext;
import com.google.cloud.spanner.ResultSet;
import com.google.cloud.spanner.Statement;
import com.google.cloud.spanner.Struct;
import org.junit.Before;
import org.junit.Test;

import org.springframework.cloud.gcp.data.spanner.core.convert.SpannerConverter;
import org.springframework.cloud.gcp.data.spanner.core.mapping.SpannerColumn;
import org.springframework.cloud.gcp.data.spanner.core.mapping.SpannerMappingContext;
import org.springframework.cloud.gcp.data.spanner.core.mapping.SpannerTable;
import org.springframework.data.annotation.Id;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Order;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Chengyuan Zhao
 */
public class SpannerTemplateTests {

	private DatabaseClient databaseClient;

	private SpannerMappingContext mappingContext;

	private SpannerConverter objectMapper;

	private SpannerMutationFactory mutationFactory;

	private ReadContext readContext;

	private SpannerTemplate spannerTemplate;

	@Before
	public void setUp() {
		this.databaseClient = mock(DatabaseClient.class);
		this.mappingContext = new SpannerMappingContext();
		this.objectMapper = mock(SpannerConverter.class);
		this.mutationFactory = mock(SpannerMutationFactory.class);
		this.readContext = mock(ReadContext.class);
		when(this.databaseClient.singleUse()).thenReturn(this.readContext);
		this.spannerTemplate = new SpannerTemplate(this.databaseClient, this.mappingContext,
				this.objectMapper, this.mutationFactory);
	}

	@Test(expected = IllegalArgumentException.class)
	public void nullDatabaseClientTest() {
		new SpannerTemplate(null, this.mappingContext, this.objectMapper,
				this.mutationFactory);
	}

	@Test(expected = IllegalArgumentException.class)
	public void nullMappingContextTest() {
		new SpannerTemplate(this.databaseClient, null, this.objectMapper,
				this.mutationFactory);
	}

	@Test(expected = IllegalArgumentException.class)
	public void nullObjectMapperTest() {
		new SpannerTemplate(this.databaseClient, this.mappingContext, null,
				this.mutationFactory);
	}

	@Test(expected = IllegalArgumentException.class)
	public void nullMutationFactoryTest() {
		new SpannerTemplate(this.databaseClient, this.mappingContext, this.objectMapper,
				null);
	}

	@Test
	public void getMappingContextTest() {
		assertSame(this.mappingContext, this.spannerTemplate.getMappingContext());
	}

	@Test
	public void findSingleKeyNullTest() {
		when(this.readContext.read(any(), any(), any())).thenReturn(null);
		assertNull(this.spannerTemplate.find(TestEntity.class, Key.of("key")));
	}

	@Test
	public void findSingleKeyTest() {
		Struct struct = mock(Struct.class);
		TestEntity result = new TestEntity();
		when(this.readContext.readRow(any(), any(), any())).thenReturn(struct);
		when(this.objectMapper.read(eq(TestEntity.class), same(struct))).thenReturn(result);
		TestEntity entity = this.spannerTemplate.find(TestEntity.class, Key.of("key"));
		assertSame(result, entity);
	}

	@Test
	public void findMultipleKeysTest() {
		ResultSet results = mock(ResultSet.class);
		ReadOption readOption = mock(ReadOption.class);
		KeySet keySet = KeySet.singleKey(Key.of("key"));
		when(this.readContext.read(any(), any(), any(), any())).thenReturn(results);
		this.spannerTemplate.find(TestEntity.class, keySet, readOption);
		verify(this.objectMapper, times(1)).mapToList(same(results),
				eq(TestEntity.class));
		verify(this.readContext, times(1)).read(eq("custom_test_table"), same(keySet),
				any(), same(readOption));
	}

	@Test
	public void findByStatementTest() {
		ResultSet results = mock(ResultSet.class);
		QueryOption queryOption = mock(QueryOption.class);
		Statement statement = Statement.of("test");
		when(this.readContext.executeQuery(any(), any())).thenReturn(results);
		this.spannerTemplate.find(TestEntity.class, statement, queryOption);
		verify(this.objectMapper, times(1)).mapToList(same(results),
				eq(TestEntity.class));
		verify(this.readContext, times(1)).executeQuery(same(statement),
				same(queryOption));
	}

	@Test
	public void findBySqlString() {
		QueryOption queryOption = mock(QueryOption.class);
		SpannerTemplate spyTemplate = spy(this.spannerTemplate);
		spyTemplate.find(TestEntity.class, "test", queryOption);
		verify(spyTemplate).find(eq(TestEntity.class), eq(Statement.of("test")),
				same(queryOption));
	}

	@Test
	public void findAllTest() {
		SpannerTemplate spyTemplate = spy(this.spannerTemplate);
		ReadOption readOption = mock(ReadOption.class);
		spyTemplate.findAll(TestEntity.class, readOption);
		verify(spyTemplate, times(1)).find(eq(TestEntity.class), eq(KeySet.all()),
				same(readOption));
	}

	@Test
	public void insertTest() {
		Mutation mutation = Mutation.newInsertBuilder("custom_test_table").build();
		TestEntity entity = new TestEntity();
		when(this.mutationFactory.insert(entity)).thenReturn(mutation);
		this.spannerTemplate.insert(entity);
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void updateTest() {
		Mutation mutation = Mutation.newUpdateBuilder("custom_test_table").build();
		TestEntity entity = new TestEntity();
		when(this.mutationFactory.update(entity, null)).thenReturn(mutation);
		this.spannerTemplate.update(entity);
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void updateColumnsArrayTest() {
		Mutation mutation = Mutation.newInsertOrUpdateBuilder("custom_test_table")
				.build();
		TestEntity entity = new TestEntity();
		when(this.mutationFactory.update(same(entity),
				eq(Optional.of(new HashSet<>(Arrays.asList(new String[] { "a", "b" }))))))
						.thenReturn(mutation);
		this.spannerTemplate.update(entity, "a", "b");
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void updateColumnsSetTest() {
		Mutation mutation = Mutation.newInsertOrUpdateBuilder("custom_test_table")
				.build();
		TestEntity entity = new TestEntity();
		Set<String> cols = new HashSet<>(Arrays.asList(new String[] { "a", "b" }));
		when(this.mutationFactory.update(same(entity), eq(Optional.of(cols))))
				.thenReturn(mutation);
		this.spannerTemplate.update(entity, Optional.of(cols));
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void upsertTest() {
		Mutation mutation = Mutation.newInsertOrUpdateBuilder("custom_test_table")
				.build();
		TestEntity entity = new TestEntity();
		when(this.mutationFactory.upsert(same(entity), isNull())).thenReturn(mutation);
		this.spannerTemplate.upsert(entity);
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void upsertColumnsArrayTest() {
		Mutation mutation = Mutation.newInsertOrUpdateBuilder("custom_test_table")
				.build();
		TestEntity entity = new TestEntity();
		when(this.mutationFactory.upsert(same(entity),
				eq(Optional.of(new HashSet<>(Arrays.asList(new String[] { "a", "b" }))))))
						.thenReturn(mutation);
		this.spannerTemplate.upsert(entity, "a", "b");
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void upsertColumnsSetTest() {
		Mutation mutation = Mutation.newInsertOrUpdateBuilder("custom_test_table")
				.build();
		TestEntity entity = new TestEntity();
		Set<String> cols = new HashSet<>(Arrays.asList(new String[] { "a", "b" }));
		when(this.mutationFactory.upsert(same(entity), eq(Optional.of(cols))))
				.thenReturn(mutation);
		this.spannerTemplate.upsert(entity, Optional.of(cols));
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void deleteByKeyTest() {
		Key key = Key.of("key");
		Mutation mutation = Mutation.delete("custom_test_table", key);
		when(this.mutationFactory.delete(eq(TestEntity.class), same(key)))
				.thenReturn(mutation);
		this.spannerTemplate.delete(TestEntity.class, key);
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void deleteObjectTest() {
		Mutation mutation = Mutation.delete("custom_test_table", Key.of("key"));
		TestEntity entity = new TestEntity();
		when(this.mutationFactory.delete(entity)).thenReturn(mutation);
		this.spannerTemplate.delete(entity);
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void deleteEntitiesTest() {
		Mutation mutation = Mutation.delete("custom_test_table", Key.of("key"));
		Iterable<TestEntity> entities = new ArrayList<TestEntity>();
		when(this.mutationFactory.delete(eq(TestEntity.class), same(entities)))
				.thenReturn(mutation);
		this.spannerTemplate.delete(TestEntity.class, entities);
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void deleteKeysTest() {
		KeySet keys = KeySet.newBuilder().addKey(Key.of("key1")).addKey(Key.of("key2"))
				.build();
		Mutation mutation = Mutation.delete("custom_test_table", keys);
		when(this.mutationFactory.delete(eq(TestEntity.class), same(keys)))
				.thenReturn(mutation);
		this.spannerTemplate.delete(TestEntity.class, keys);
		verify(this.databaseClient, times(1)).write(eq(Arrays.asList(mutation)));
	}

	@Test
	public void countTest() {
		ResultSet results = mock(ResultSet.class);
		when(this.readContext
				.executeQuery(eq(Statement.of("select count(*) from custom_test_table"))))
						.thenReturn(results);
		this.spannerTemplate.count(TestEntity.class);
		verify(results, times(1)).next();
		verify(results, times(1)).getLong(eq(0));
		verify(results, times(1)).close();
	}

	@Test
	public void findAllSortWithLimitsOffsetTest() {
		SpannerTemplate spyTemplate = spy(this.spannerTemplate);
		QueryOption queryOption = mock(QueryOption.class);
		Sort sort = Sort.by(Order.asc("id"), Order.desc("something"), Order.asc("other"));

		doAnswer(invocation -> {
			Statement statement = invocation.getArgument(1);
			assertEquals(
					"SELECT * FROM custom_test_table ORDER BY id ASC , custom_col DESC , other ASC LIMIT 3 OFFSET 5;",
					statement.getSql());
			return null;
		}).when(spyTemplate).find(eq(TestEntity.class), (Statement) any(), any());

		spyTemplate.findAll(TestEntity.class, sort, OptionalLong.of(3),
				OptionalLong.of(5), queryOption);
		verify(spyTemplate, times(1)).find(eq(TestEntity.class), (Statement) any(),
				any());
	}

	@Test
	public void findAllSortTest() {
		SpannerTemplate spyTemplate = spy(this.spannerTemplate);
		QueryOption queryOption = mock(QueryOption.class);
		Sort sort = mock(Sort.class);

		spyTemplate.findAll(TestEntity.class, sort, queryOption);
		verify(spyTemplate, times(1)).findAll(eq(TestEntity.class), same(sort),
				eq(OptionalLong.empty()), eq(OptionalLong.empty()), same(queryOption));
	}

	@Test
	public void findAllPageableTest() {
		SpannerTemplate spyTemplate = spy(this.spannerTemplate);
		QueryOption queryOption = mock(QueryOption.class);
		Sort sort = mock(Sort.class);
		Pageable pageable = mock(Pageable.class);

		long offset = 5L;
		int limit = 3;
		long total = 9999;

		when(pageable.getOffset()).thenReturn(offset);
		when(pageable.getPageSize()).thenReturn(limit);
		when(pageable.getSort()).thenReturn(sort);

		TestEntity t1 = new TestEntity();
		t1.id = "a";
		TestEntity t2 = new TestEntity();
		t2.id = "b";
		TestEntity t3 = new TestEntity();
		t3.id = "c";

		List<TestEntity> items = new ArrayList<>();
		items.add(t1);
		items.add(t2);
		items.add(t3);

		doReturn(items).when(spyTemplate).findAll(eq(TestEntity.class), same(sort),
				eq(OptionalLong.of(limit)), eq(OptionalLong.of(offset)),
				same(queryOption));
		doReturn(total).when(spyTemplate).count(eq(TestEntity.class));

		Page page = spyTemplate.findAll(TestEntity.class, pageable, queryOption);
		assertEquals(limit, page.getPageable().getPageSize());
		assertEquals(total, page.getTotalElements());
		assertEquals("a", ((TestEntity) page.getContent().get(0)).id);
		assertEquals("b", ((TestEntity) page.getContent().get(1)).id);
		assertEquals("c", ((TestEntity) page.getContent().get(2)).id);
	}

	@SpannerTable(name = "custom_test_table")
	private static class TestEntity {
		@Id
		String id;

		@SpannerColumn(name = "custom_col")
		String something;

		@SpannerColumn(name = "")
		String other;
	}
}
