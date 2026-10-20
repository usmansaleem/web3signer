/*
 * Copyright 2023 ConsenSys AG.
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
import tech.pegasys.web3signer.signing.EthSecpArtifactSigner;
import tech.pegasys.web3signer.signing.K256ArtifactSigner;
import tech.pegasys.web3signer.signing.secp256k1.filebased.CredentialSigner;
import tech.pegasys.web3signer.signing.secp256k1.util.JsonFilesUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.crypto.exception.CipherException;

/**
 * Bulk-loads SECP256K1 v3 keystores. An instance remembers what was loaded from each directory so a
 * keystore or source that fails to load keeps its previously loaded key, while a keystore that is
 * no longer listed is dropped. Loads must be serialized by the caller.
 *
 * <p>An instance must only ever be used with one {@code ethereumSECPCompatible} value, i.e. either
 * with {@link #loadV3KeystoresUsingPasswordFileOrDir} or with {@link #loadECDSAProxyKeystores},
 * because the cached signers are keyed by directory only.
 */
public class SecpV3KeystoresBulkLoader {
  private static final Logger LOG = LogManager.getLogger();

  private final KeystoreSignerCache cache = new KeystoreSignerCache();

  /**
   * Bulk-load Ethereum compatible SECP Artifact Signers from encrypted v3 keystores.
   *
   * @param keystoresPath Path to the directory containing the v3 keystores
   * @param pwrdFileOrDirPath Path to the password file or directory containing the passwords for
   *     the v3 keystores
   * @return MappedResults containing the loaded ArtifactSigners
   */
  public MappedResults<ArtifactSigner> loadV3KeystoresUsingPasswordFileOrDir(
      final Path keystoresPath, final Path pwrdFileOrDirPath) {
    return loadV3KeystoresUsingPasswordFileOrDir(keystoresPath, pwrdFileOrDirPath, true);
  }

  /**
   * Bulk-load generic SECP Artifact Signers from encrypted v3 keystores that can be used by Commit
   * Boost API. It uses compressed public key as identifier and apply SHA256 digest on the message
   * before signing.
   *
   * @param keystoresPath Path to the directory containing the v3 keystores
   * @param pwrdFileOrDirPath Path to the password file or directory containing the passwords for
   *     the v3 keystores
   * @return MappedResults containing the loaded ArtifactSigners
   */
  public MappedResults<ArtifactSigner> loadECDSAProxyKeystores(
      final Path keystoresPath, final Path pwrdFileOrDirPath) {
    return loadV3KeystoresUsingPasswordFileOrDir(keystoresPath, pwrdFileOrDirPath, false);
  }

  private MappedResults<ArtifactSigner> loadV3KeystoresUsingPasswordFileOrDir(
      final Path keystoresPath,
      final Path pwrdFileOrDirPath,
      final boolean ethereumSECPCompatible) {
    if (!Files.exists(pwrdFileOrDirPath)) {
      LOG.error("Password file or directory doesn't exist.");
      return cache.retainAllOnSourceError(keystoresPath);
    }

    final List<Path> keystoresFiles;
    try {
      keystoresFiles = JsonFilesUtil.loadJsonExtPaths(keystoresPath);
    } catch (final IOException e) {
      LOG.error("Error listing v3 keystores paths {}", keystoresPath);
      return cache.retainAllOnSourceError(keystoresPath);
    }

    final PasswordReader passwordReader;
    if (Files.isDirectory(pwrdFileOrDirPath)) {
      passwordReader = passwordFile -> Files.readString(pwrdFileOrDirPath.resolve(passwordFile));
    } else if (Files.isRegularFile(pwrdFileOrDirPath)) {
      try {
        final String password = Files.readString(pwrdFileOrDirPath);
        passwordReader = passwordFile -> password;
      } catch (final IOException e) {
        LOG.error("Unable to read password file.", e);
        return cache.retainAllOnSourceError(keystoresPath);
      }
    } else {
      LOG.error(
          "Unexpected path. Expecting it to be a regular file or directory. {}", pwrdFileOrDirPath);
      return cache.retainAllOnSourceError(keystoresPath);
    }

    return cache.load(
        keystoresPath,
        keystoresFiles,
        keystoreFile ->
            createSecpArtifactSigner(keystoreFile, passwordReader, ethereumSECPCompatible));
  }

  private static Optional<ArtifactSigner> createSecpArtifactSigner(
      final Path v3KeystorePath,
      final PasswordReader passwordReader,
      final boolean ethereumSECPCompatible) {
    try {
      final String fileNameWithoutExt =
          FilenameUtils.removeExtension(v3KeystorePath.getFileName().toString());

      final String password = passwordReader.readPassword(fileNameWithoutExt + ".txt");

      final Credentials credentials =
          WalletUtils.loadCredentials(password, v3KeystorePath.toFile());
      final ArtifactSigner artifactSigner =
          ethereumSECPCompatible
              ? new EthSecpArtifactSigner(new CredentialSigner(credentials))
              : new K256ArtifactSigner(credentials.getEcKeyPair());

      return Optional.of(artifactSigner);
    } catch (final IOException | CipherException | RuntimeException e) {
      LOG.error("Error loading v3 keystore {}", v3KeystorePath, e);
      return Optional.empty();
    }
  }
}
