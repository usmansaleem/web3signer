/*
 * Copyright 2022 ConsenSys AG.
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

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.KeyStoreLoader;
import tech.pegasys.web3signer.bls.keystore.KeyStoreValidationException;
import tech.pegasys.web3signer.bls.keystore.model.KeyStoreData;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.config.metadata.SignerOrigin;
import tech.pegasys.web3signer.signing.secp256k1.util.JsonFilesUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Bulk-loads BLS keystores. One instance per configured keystore source, long-lived (held by the
 * runner): it remembers what was loaded from each directory so a keystore or source that fails to
 * load keeps its previously loaded key, while a keystore that is no longer listed is dropped. Loads
 * must be serialized by the caller.
 */
public class BlsKeystoreBulkLoader {
  private static final Logger LOG = LogManager.getLogger();

  private final KeystoreSignerCache cache = new KeystoreSignerCache();

  public MappedResults<ArtifactSigner> loadKeystoresUsingPasswordDir(
      final Path keystoresDirectory, final Path passwordsDirectory) {
    final List<Path> keystoreFiles;
    try {
      keystoreFiles = JsonFilesUtil.loadJsonExtPaths(keystoresDirectory);
    } catch (final IOException e) {
      LOG.error("Error reading keystore files", e);
      return cache.retainAllOnSourceError(keystoresDirectory);
    }

    return cache.load(
        keystoresDirectory,
        keystoreFiles,
        keystoreFile ->
            createSignerForKeystore(
                keystoreFile,
                keystorePassword ->
                    Files.readString(passwordsDirectory.resolve(keystorePassword))));
  }

  public MappedResults<ArtifactSigner> loadKeystoresUsingPasswordFile(
      final Path keystoresDirectory, final Path passwordFile) {
    final List<Path> keystoreFiles;
    try {
      keystoreFiles = JsonFilesUtil.loadJsonExtPaths(keystoresDirectory);
    } catch (final IOException e) {
      LOG.error("Error reading keystore files", e);
      return cache.retainAllOnSourceError(keystoresDirectory);
    }

    final String password;
    try {
      password = Files.readString(passwordFile);
    } catch (final IOException e) {
      LOG.error("Unable to read password file", e);
      return cache.retainAllOnSourceError(keystoresDirectory);
    }

    return cache.load(
        keystoresDirectory,
        keystoreFiles,
        keystoreFile -> createSignerForKeystore(keystoreFile, keystorePassword -> password));
  }

  /**
   * Forgets the previously loaded key with the given identifier, so that it is not re-supplied when
   * a later load fails. Called when the key was removed at runtime (e.g. via the key manager API).
   * Must be called from the thread that serializes loads.
   *
   * @param identifier identifier of the key to forget
   */
  public void evict(final String identifier) {
    cache.evict(identifier);
  }

  private static Optional<ArtifactSigner> createSignerForKeystore(
      final Path keystoreFile, final PasswordReader passwordReader) {
    try {
      LOG.debug("Loading keystore {}", keystoreFile);
      final KeyStoreData keyStoreData = KeyStoreLoader.loadFromFile(keystoreFile.toUri());
      final String fileNameWithoutExt =
          FilenameUtils.removeExtension(keystoreFile.getFileName().toString());
      final String password = passwordReader.readPassword(fileNameWithoutExt + ".txt");
      final BLSKeyPair keyPair = KeyStore.decrypt(password, keyStoreData);
      return Optional.of(new BlsArtifactSigner(keyPair, SignerOrigin.FILE_KEYSTORE));
    } catch (final KeyStoreValidationException | IOException e) {
      LOG.error("Keystore could not be loaded {}", keystoreFile, e);
      return Optional.empty();
    }
  }
}
