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

import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.config.SignerSourceResult;
import tech.pegasys.web3signer.signing.config.SignerSourceResult.LoadedSigner;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Function;

/** Loads keystore files in parallel; reports each signer's file and the files that failed. */
final class KeystoreFilesLoader {

  private KeystoreFilesLoader() {}

  /**
   * @param loadFile loads one keystore file; empty if it failed. Must not throw, so that one file
   *     cannot fail the whole load.
   */
  static SignerSourceResult load(
      final String source,
      final List<Path> keystoreFiles,
      final Function<Path, Optional<ArtifactSigner>> loadFile) {
    final ConcurrentLinkedQueue<LoadedSigner> signers = new ConcurrentLinkedQueue<>();
    final Set<String> failedFiles = ConcurrentHashMap.newKeySet();

    keystoreFiles.parallelStream()
        .forEach(
            keystoreFile -> {
              final Optional<ArtifactSigner> signer = loadFile.apply(keystoreFile);
              if (signer.isPresent()) {
                signers.add(new LoadedSigner(signer.get(), Optional.of(keystoreFile.toString())));
              } else {
                failedFiles.add(keystoreFile.toString());
              }
            });

    return new SignerSourceResult(
        source, List.copyOf(signers), failedFiles, failedFiles.size(), false);
  }
}
