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

package org.springframework.cloud.gcp.core;

import java.io.ByteArrayInputStream;
import java.util.Base64;

import com.google.api.gax.core.CredentialsProvider;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Parses Cloud Foundry's VCAP_SERVICES environment variable to return the Google Cloud Platform
 * configuration.
 *
 * @author João André Martins
 */
public class DefaultCfConfiguration implements CfConfiguration {

	private static final Log LOGGER = LogFactory.getLog(DefaultCfConfiguration.class);

	private JsonObject configurationJsonObject;

	public DefaultCfConfiguration(String jsonConfiguration) {
		this.configurationJsonObject = new JsonParser().parse(jsonConfiguration).getAsJsonObject();
	}

	@Override
	public CredentialsProvider getStorageCredentialsProvider() {
		return parseCredentialsProviderFromVcapJson("google-storage");
	}

	@Override
	public CredentialsProvider getPubSubCredentialsProvider() {
		return parseCredentialsProviderFromVcapJson("google-pubsub");
	}

	@Override
	public CredentialsProvider getCloudSqlMySqlCredentialsProvider() {
		return parseCredentialsProviderFromVcapJson("google-cloudsql-mysql");
	}

	@Override
	public CredentialsProvider getCloudSqlPostgreSqlCredentialsProvider() {
		return parseCredentialsProviderFromVcapJson("google-cloudsql-postgresql");
	}

	@Override
	public CredentialsProvider getTraceCredentialsProvider() {
		return parseCredentialsProviderFromVcapJson("google-stackdriver-trace");
	}

	// TODO(joaomartins): Rename and document this.
	private CredentialsProvider parseCredentialsProviderFromVcapJson(String jsonKey) {
		byte[] privateKeyData = getPrivateKeyDataForServiceFromVcapJson(jsonKey);

		return privateKeyData != null
				? () -> GoogleCredentials.fromStream(new ByteArrayInputStream(privateKeyData))
				: null;
	}

	public byte[] getPrivateKeyDataForServiceFromVcapJson(String jsonKey) {
		if (this.configurationJsonObject.has(jsonKey)) {
			JsonElement serviceElement = this.configurationJsonObject.get(jsonKey);
			if (serviceElement.isJsonArray() && ((JsonArray) serviceElement).size() > 0) {
				JsonElement jsonCredentialsElement = ((JsonArray) serviceElement).get(0);
				if (jsonCredentialsElement.isJsonObject()
						&& ((JsonObject) jsonCredentialsElement).has("credentials")) {
					JsonObject jsonCredentialsObject =
							(JsonObject) ((JsonObject) jsonCredentialsElement).get("credentials");
					if (jsonCredentialsObject.has("PrivateKeyData")) {
						LOGGER.info("Pivotal Cloud Foundry credentials for " + jsonKey
								+ " found: " + jsonCredentialsObject.get("Name"));
						return Base64.getDecoder().decode(
								jsonCredentialsObject.get("PrivateKeyData").getAsString());
					}
				}
			}
		}

		return null;
	}
}
