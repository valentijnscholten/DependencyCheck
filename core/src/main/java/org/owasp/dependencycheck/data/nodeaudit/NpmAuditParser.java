/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import javax.json.JsonArray;
import javax.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Parser for NPM Audit API response. This parser is derived from:
 * https://github.com/DependencyTrack/dependency-track/blob/master/src/main/java/org/owasp/dependencytrack/parser/npm/audit/NpmAuditParser.java
 *
 * @author Steve Springett
 */
public class NpmAuditParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NpmAuditParser.class);

    /**
     * Parses the JSON response from the NPM Audit API.
     *
     * @param jsonResponse the JSON node to parse
     * @return an AdvisoryResults object
     */
    public List<Advisory> parse(JsonObject jsonResponse) {
        LOGGER.debug("Parsing JSON node");
        final List<Advisory> advisories = new ArrayList<>();
        final JsonObject jsonAdvisories = jsonResponse.getJsonObject("advisories");
        final Iterator<String> keys = jsonAdvisories.keySet().iterator();
        while (keys.hasNext()) {
            final String key = keys.next();
            final Advisory advisory = parseAdvisory(jsonAdvisories.getJsonObject(key));
            advisories.add(advisory);
        }
        return advisories;
    }

    /**
     * Parses the advisory from Node Audit.
     *
     * @param object the JSON object containing the advisory
     * @return the Advisory object
     */
    private Advisory parseAdvisory(JsonObject object) {
        final Advisory advisory = new Advisory();
        advisory.setId(object.getInt("id"));
        advisory.setOverview(object.getString("overview", null));
        advisory.setReferences(object.getString("references", null));
        advisory.setCreated(object.getString("created", null));
        advisory.setUpdated(object.getString("updated", null));
        advisory.setRecommendation(object.getString("recommendation", null));
        advisory.setTitle(object.getString("title", null));
        //advisory.setFoundBy(object.getString("author", null));
        //advisory.setReportedBy(object.getString("author", null));
        advisory.setModuleName(object.getString("module_name", null));
        advisory.setVulnerableVersions(object.getString("vulnerable_versions", null));
        advisory.setPatchedVersions(object.getString("patched_versions", null));
        advisory.setAccess(object.getString("access", null));
        advisory.setSeverity(object.getString("severity", null));
        advisory.setCwe(object.getString("cwe", null));

        final JsonArray findings = object.getJsonArray("findings");
        for (int i = 0; i < findings.size(); i++) {
            final JsonObject finding = findings.getJsonObject(i);
            final String version = finding.getString("version", null);
            final JsonArray paths = finding.getJsonArray("paths");
            for (int j = 0; j < paths.size(); j++) {
                final String path = paths.getString(j);
                if (path != null && path.equals(advisory.getModuleName())) {
                    advisory.setVersion(version);
                }
            }
        }

        final JsonArray jsonCves = object.getJsonArray("cves");
        final List<String> stringCves = new ArrayList<>();
        if (jsonCves != null) {
            for (int j = 0; j < jsonCves.size(); j++) {
                stringCves.add(jsonCves.getString(j));
            }
            advisory.setCves(stringCves);
        }
        return advisory;
    }
}
