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
		return getCredentialsProviderFromVcapJson("google-storage");
	}

	@Override
	public CredentialsProvider getPubSubCredentialsProvider() {
		return getCredentialsProviderFromVcapJson("google-pubsub");
	}

	@Override
	public CredentialsProvider getCloudSqlMySqlCredentialsProvider() {
		return getCredentialsProviderFromVcapJson("google-cloudsql-mysql");
	}

	@Override
	public CredentialsProvider getCloudSqlPostgreSqlCredentialsProvider() {
		return getCredentialsProviderFromVcapJson("google-cloudsql-postgresql");
	}

	@Override
	public CredentialsProvider getTraceCredentialsProvider() {
		return getCredentialsProviderFromVcapJson("google-stackdriver-trace");
	}

	@Override
	public CredentialsProvider getSpannerCredentialsProvider() {
		return getCredentialsProviderFromVcapJson("google-spanner");
	}

	/**
	 * Builds a {@link CredentialsProvider} for a Cloud Foundry service provisioned by the GCP
	 * service broker.
	 * @param jsonKey the name of the GCP service created by the CF GCP service broker
	 * @return a provider for the credentials provisioned by the GCP service broker
	 */
	private CredentialsProvider getCredentialsProviderFromVcapJson(String jsonKey) {
		byte[] privateKeyData = getPrivateKeyDataForServiceFromVcapJson(jsonKey);

		return privateKeyData != null
				? () -> GoogleCredentials.fromStream(new ByteArrayInputStream(privateKeyData))
				: null;
	}

	/**
	 * Given the key of the GCP Cloud Foundry service broker (e.g., "google-storage"), returns
	 * the decoded credentials.PrivateKeyData JSON field which can be used to construct a
	 * Google credentials object.
	 * @param jsonKey the name of the GCP service created by the CF GCP service broker
	 * @return a byte[] containing a decoded string using the ISO_8859_1 encoding
	 */
	public byte[] getPrivateKeyDataForServiceFromVcapJson(String jsonKey) {
		if (this.configurationJsonObject.has("VCAP_SERVICES")) {
			JsonObject vcapServices =
					(JsonObject) this.configurationJsonObject.get("VCAP_SERVICES");
			if (vcapServices.has(jsonKey)) {
				JsonArray serviceArray = (JsonArray) vcapServices.get(jsonKey);
				// TODO(joaomartins): What should be the behaviour when the same service is bound
				// multiple times to the same app?
				if (serviceArray.size() > 0) {
					JsonObject serviceEntry = (JsonObject) serviceArray.get(0);
					if (serviceEntry.has("credentials")) {
						JsonObject encodedCredentials =
								(JsonObject) serviceEntry.get("credentials");
						if (encodedCredentials.has("PrivateKeyData")) {
							LOGGER.info("Pivotal Cloud Foundry credentials for " + jsonKey
									+ " found: " + encodedCredentials.get("Name"));
							return Base64.getDecoder().decode(
									encodedCredentials.get("PrivateKeyData").getAsString());
						}
					}
				}
			}
		}

		return null;
	}
}
