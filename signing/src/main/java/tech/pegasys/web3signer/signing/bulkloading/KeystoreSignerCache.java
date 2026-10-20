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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Per keystore directory: the signer loaded from each keystore file on the last load plus the
 * file's modification time. Unchanged files are not decrypted again; a file or source that fails to
 * load keeps its previously loaded signer instead of looking deleted.
 *
 * <p>Single writer: loads are serialized by the caller (DefaultArtifactSignerProvider's
 * single-threaded executor; POST /reload rejects overlapping calls with 409).
 */
final class KeystoreSignerCache {
  private static final Logger LOG = LogManager.getLogger();

  private record CachedKeystore(FileTime lastModifiedTime, ArtifactSigner signer) {}

  // keystore directory -> keystore file -> last loaded entry
  private volatile Map<Path, Map<Path, CachedKeystore>> lastLoadedByDirectory = Map.of();

  /**
   * Loads the listed files via {@code loadFile}, skipping files whose modification time is
   * unchanged since the last load. A failing file counts as one error and, if it loaded on a
   * previous call for this directory, keeps its previous signer. Files that are not listed are
   * dropped.
   */
  MappedResults<ArtifactSigner> load(
      final Path keystoresDirectory,
      final List<Path> keystoreFiles,
      final Function<Path, Optional<ArtifactSigner>> loadFile) {
    final Path directoryKey = key(keystoresDirectory);
    final Map<Path, CachedKeystore> previous =
        lastLoadedByDirectory.getOrDefault(directoryKey, Map.of());
    final Map<Path, CachedKeystore> loaded = new ConcurrentHashMap<>();
    final AtomicInteger errorCount = new AtomicInteger();
    final AtomicInteger retainedCount = new AtomicInteger();

    keystoreFiles.parallelStream()
        .forEach(
            keystoreFile -> {
              final Path fileKey = key(keystoreFile);
              final FileTime modifiedTime = lastModifiedTime(keystoreFile);
              final CachedKeystore cached = previous.get(fileKey);
              if (cached != null && modifiedTime.equals(cached.lastModifiedTime())) {
                loaded.put(fileKey, cached);
                return;
              }

              final Optional<ArtifactSigner> signer = loadFile.apply(keystoreFile);
              if (signer.isPresent()) {
                loaded.put(fileKey, new CachedKeystore(modifiedTime, signer.get()));
                return;
              }

              errorCount.incrementAndGet();
              if (cached != null) {
                // keeps the old modified time, so the file is decrypted again on the next load
                loaded.put(fileKey, cached);
                retainedCount.incrementAndGet();
                LOG.debug(
                    "Keystore {} failed to load; retaining previously loaded key {}",
                    keystoreFile,
                    cached.signer().getIdentifier());
              }
            });

    if (retainedCount.get() > 0) {
      LOG.warn(
          "{} keystore file(s) in {} failed to load; retaining their {} previously loaded key(s)",
          errorCount.get(),
          keystoresDirectory,
          retainedCount.get());
    }

    final Map<Path, Map<Path, CachedKeystore>> updated = new HashMap<>(lastLoadedByDirectory);
    updated.put(directoryKey, Map.copyOf(loaded));
    lastLoadedByDirectory = Map.copyOf(updated);

    return MappedResults.newInstance(
        loaded.values().stream().map(CachedKeystore::signer).toList(), errorCount.get());
  }

  /**
   * Whole-source failure (listing or shared password unreadable): nothing can be attributed to a
   * file, so return all signers of the previous load for this directory with an error count of one.
   */
  MappedResults<ArtifactSigner> retainAllOnSourceError(final Path keystoresDirectory) {
    final Map<Path, CachedKeystore> previous =
        lastLoadedByDirectory.getOrDefault(key(keystoresDirectory), Map.of());
    if (!previous.isEmpty()) {
      LOG.warn(
          "Keystore source {} could not be loaded; retaining {} previously loaded key(s)",
          keystoresDirectory,
          previous.size());
    }
    return MappedResults.newInstance(
        previous.values().stream().map(CachedKeystore::signer).toList(), 1);
  }

  private static Path key(final Path path) {
    return path.toAbsolutePath().normalize();
  }

  private static FileTime lastModifiedTime(final Path file) {
    try {
      return Files.getLastModifiedTime(file);
    } catch (final IOException e) {
      // forces the file to be loaded
      return FileTime.from(Instant.now());
    }
  }
}
