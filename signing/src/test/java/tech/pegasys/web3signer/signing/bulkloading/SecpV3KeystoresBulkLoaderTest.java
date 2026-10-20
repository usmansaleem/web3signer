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

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.web3j.crypto.WalletUtils;

public class SecpV3KeystoresBulkLoaderTest {

  @TempDir Path keystoreDir;
  @TempDir Path passwordDir;

  private final SecpV3KeystoresBulkLoader loader = new SecpV3KeystoresBulkLoader();

  @BeforeEach
  void initV3KeystoresAndPasswordFiles() throws Exception {
    for (int i = 0; i < 4; i++) {
      final String fileName =
          WalletUtils.generateLightNewWalletFile("test123", keystoreDir.toFile());

      final Path passwordFile =
          passwordDir.resolve(fileName.substring(0, fileName.lastIndexOf(".json")) + ".txt");
      Files.writeString(passwordFile, "test123");

      // write files in wallet dir that will be ignored by bulk loading logic
      Files.writeString(keystoreDir.resolve(i + ".txt"), "ignored");
    }
  }

  @Test
  void loadSecpV3KeystoresWithPasswordFilesFromDir() {
    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordDir);

    assertThat(results.getValues()).hasSize(4);
    assertThat(results.getErrorCount()).isZero();
  }

  @Test
  void loadSecpV3KeystoresWithPasswordFile() throws IOException {
    final Path passwordFile;
    try (Stream<Path> passwordFiles = Files.list(passwordDir)) {
      passwordFile = passwordFiles.findAny().orElseThrow();
    }

    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordFile);

    assertThat(results.getValues()).hasSize(4);
    assertThat(results.getErrorCount()).isZero();
  }

  @Test
  void emptyResultsWhenKeystoresDirIsEmpty(@TempDir Path emptyDir) throws IOException {
    final Path passwordFile;
    try (Stream<Path> passwordFiles = Files.list(passwordDir)) {
      passwordFile = passwordFiles.findAny().orElseThrow();
    }

    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(emptyDir, passwordFile);

    assertThat(results.getValues()).isEmpty();
    assertThat(results.getErrorCount()).isZero();
  }

  @Test
  void errorResultsWhenV3KeystoreFileIsInvalid() throws IOException {
    for (int i = 0; i < 4; i++) {
      Files.writeString(keystoreDir.resolve(i + ".json"), "invalid content");
    }

    final Path passwordFile;
    try (Stream<Path> passwordFiles = Files.list(passwordDir)) {
      passwordFile = passwordFiles.findAny().orElseThrow();
    }

    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordFile);

    assertThat(results.getValues()).hasSize(4);
    assertThat(results.getErrorCount()).isEqualTo(4);
  }

  @Test
  void errorResultsWhenPasswordIsInvalid() throws IOException {
    Path passwordFile = Files.writeString(passwordDir.resolve("password.txt"), "invalid");

    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordFile);

    assertThat(results.getValues()).isEmpty();
    assertThat(results.getErrorCount()).isEqualTo(4);
  }

  @Test
  void errorResultsWhenPasswordFileIsMissing() {
    Path passwordFile = passwordDir.resolve("password.txt");

    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordFile);

    assertThat(results.getValues()).isEmpty();
    assertThat(results.getErrorCount()).isEqualTo(1);
  }

  @Test
  void errorResultsWhenCorrespondingPasswordFileIsMissing() throws IOException {
    // delete one password file
    try (Stream<Path> passwordFiles = Files.list(passwordDir)) {
      Files.delete(passwordFiles.findAny().orElseThrow());
    }

    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordDir);

    assertThat(results.getValues()).hasSize(3);
    assertThat(results.getErrorCount()).isEqualTo(1);
  }

  @Test
  void errorResultsWhenPasswordDirIsEmpty(@TempDir Path emptyPasswordDir) {
    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, emptyPasswordDir);

    assertThat(results.getValues()).isEmpty();
    assertThat(results.getErrorCount()).isEqualTo(4);
  }

  @Test
  void errorResultsWhenPasswordDirIsMissing() {
    final MappedResults<ArtifactSigner> results =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordDir.resolve("/invalid"));

    assertThat(results.getValues()).isEmpty();
    assertThat(results.getErrorCount()).isEqualTo(1);
  }

  @Test
  void unreadablePasswordFileRetainsPreviouslyLoadedKeystoresUntilFixed() throws IOException {
    final Path passwordFile = Files.writeString(passwordDir.resolve("password.txt"), "test123");
    assertThat(loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordFile).getValues())
        .hasSize(4);

    Files.delete(passwordFile);
    final MappedResults<ArtifactSigner> errored =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordFile);
    assertThat(errored.getValues()).hasSize(4);
    assertThat(errored.getErrorCount()).isEqualTo(1);

    Files.writeString(passwordFile, "test123");
    Files.delete(keystoreFiles().get(0));
    final MappedResults<ArtifactSigner> recovered =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordFile);
    assertThat(recovered.getValues()).hasSize(3);
    assertThat(recovered.getErrorCount()).isZero();
  }

  @Test
  void failingKeystoreRetainsItsPreviousKeyWhileDeletedKeystoreIsRemoved() throws IOException {
    assertThat(loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordDir).getValues())
        .hasSize(4);

    final List<Path> keystores = keystoreFiles();
    final Path corrupted = keystores.get(0);
    final Path deleted = keystores.get(1);
    Files.writeString(corrupted, "invalid content");
    bumpModifiedTime(corrupted);
    Files.delete(deleted);

    final MappedResults<ArtifactSigner> errored =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordDir);
    assertThat(errored.getValues()).hasSize(3);
    assertThat(errored.getErrorCount()).isEqualTo(1);

    Files.delete(corrupted);
    final MappedResults<ArtifactSigner> recovered =
        loader.loadV3KeystoresUsingPasswordFileOrDir(keystoreDir, passwordDir);
    assertThat(recovered.getValues()).hasSize(2);
    assertThat(recovered.getErrorCount()).isZero();
  }

  private List<Path> keystoreFiles() throws IOException {
    try (Stream<Path> files = Files.list(keystoreDir)) {
      return files.filter(path -> path.toString().endsWith(".json")).sorted().toList();
    }
  }

  private static void bumpModifiedTime(final Path file) throws IOException {
    Files.setLastModifiedTime(
        file, FileTime.fromMillis(Files.getLastModifiedTime(file).toMillis() + 1000));
  }
}
