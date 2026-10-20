/*
 * Copyright 2026 Consensys Incorporated.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.web3signer.signing.bulkloading;

import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Retention for key vault sources (Azure/AWS/GCP secrets, AWS KMS) where a failure cannot be
 * attributed to a secret: the vault loaders only count errors. While a vault reports any error, the
 * keys it supplied on its previous load that are missing from the current result are kept; an
 * error-free load drops them.
 *
 * <p>One instance per vault source, long-lived. Loads must be serialized by the caller.
 */
public final class BulkLoadRetention {
  private static final Logger LOG = LogManager.getLogger();

  private final String sourceName;
  // identifier -> signer of the last returned result
  private volatile Map<String, ArtifactSigner> lastLoaded = Map.of();

  public BulkLoadRetention(final String sourceName) {
    this.sourceName = sourceName;
  }

  /**
   * Adds the previously loaded keys missing from {@code result} when the result reports errors, and
   * remembers the returned keys for the next load.
   *
   * @param result the result of loading the vault
   * @return the result, extended with retained keys if it reported errors
   */
  public MappedResults<ArtifactSigner> retainMissingOnError(
      final MappedResults<ArtifactSigner> result) {
    final List<ArtifactSigner> values = new ArrayList<>(result.getValues());

    if (result.getErrorCount() > 0) {
      final Set<String> present = new HashSet<>();
      values.forEach(signer -> present.add(signer.getIdentifier()));
      final List<ArtifactSigner> retained =
          lastLoaded.values().stream()
              .filter(signer -> !present.contains(signer.getIdentifier()))
              .toList();
      if (!retained.isEmpty()) {
        LOG.warn(
            "{} reported {} error(s); retaining {} previously loaded key(s) missing from this load",
            sourceName,
            result.getErrorCount(),
            retained.size());
        values.addAll(retained);
      }
    }

    final Map<String, ArtifactSigner> byIdentifier = new HashMap<>();
    values.forEach(signer -> byIdentifier.putIfAbsent(signer.getIdentifier(), signer));
    lastLoaded = Map.copyOf(byIdentifier);

    return MappedResults.newInstance(values, result.getErrorCount());
  }
}
