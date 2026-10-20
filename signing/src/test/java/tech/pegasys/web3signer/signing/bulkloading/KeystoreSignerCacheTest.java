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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeystoreSignerCacheTest {

  @TempDir Path dir1;
  @TempDir Path dir2;

  private final KeystoreSignerCache cache = new KeystoreSignerCache();
  private final Set<Path> failing = ConcurrentHashMap.newKeySet();
  private final List<Path> loadedFiles = new CopyOnWriteArrayList<>();
  private final Map<Path, ArtifactSigner> signerByFile = new ConcurrentHashMap<>();

  private Path a;
  private Path b;

  @BeforeEach
  void createFiles() throws IOException {
    a = Files.writeString(dir1.resolve("a.json"), "a");
    b = Files.writeString(dir1.resolve("b.json"), "b");
  }

  private Optional<ArtifactSigner> loadFile(final Path file) {
    loadedFiles.add(file);
    if (failing.contains(file)) {
      return Optional.empty();
    }
    final ArtifactSigner signer = mock(ArtifactSigner.class);
    when(signer.getIdentifier()).thenReturn(file.getFileName().toString());
    signerByFile.put(file, signer);
    return Optional.of(signer);
  }

  private MappedResults<ArtifactSigner> load(final Path directory, final Path... files) {
    return cache.load(directory, List.of(files), this::loadFile);
  }

  private static void bumpModifiedTime(final Path file) throws IOException {
    Files.setLastModifiedTime(
        file, FileTime.fromMillis(Files.getLastModifiedTime(file).toMillis() + 1000));
  }

  @Test
  void unchangedFilesAreNotLoadedAgain() {
    final MappedResults<ArtifactSigner> first = load(dir1, a, b);
    assertThat(loadedFiles).containsExactlyInAnyOrder(a, b);
    assertThat(first.getValues()).hasSize(2);
    assertThat(first.getErrorCount()).isZero();

    loadedFiles.clear();
    final MappedResults<ArtifactSigner> second = load(dir1, a, b);

    assertThat(loadedFiles).isEmpty();
    assertThat(second.getErrorCount()).isZero();
    assertThat(second.getValues()).containsExactlyInAnyOrderElementsOf(first.getValues());
  }

  @Test
  void modifiedFileIsReloaded() throws IOException {
    final List<ArtifactSigner> first = new ArrayList<>(load(dir1, a, b).getValues());

    loadedFiles.clear();
    bumpModifiedTime(a);
    final List<ArtifactSigner> second = new ArrayList<>(load(dir1, a, b).getValues());

    assertThat(loadedFiles).containsExactly(a);
    assertThat(second).hasSize(2);
    // exactly one of the two signers is new
    final Set<ArtifactSigner> unchanged = new HashSet<>(first);
    unchanged.retainAll(second);
    assertThat(unchanged).hasSize(1);
  }

  @Test
  void failedFileKeepsPreviousSignerAndIsRetriedNextLoad() throws IOException {
    final List<ArtifactSigner> first = new ArrayList<>(load(dir1, a, b).getValues());

    failing.add(a);
    bumpModifiedTime(a);
    loadedFiles.clear();
    final MappedResults<ArtifactSigner> errored = load(dir1, a, b);
    assertThat(errored.getErrorCount()).isEqualTo(1);
    assertThat(errored.getValues()).containsExactlyInAnyOrderElementsOf(first);
    assertThat(loadedFiles).containsExactly(a);

    // the old modified time is retained, so the file is loaded again
    loadedFiles.clear();
    final MappedResults<ArtifactSigner> stillErrored = load(dir1, a, b);
    assertThat(loadedFiles).containsExactly(a);
    assertThat(stillErrored.getErrorCount()).isEqualTo(1);
    assertThat(stillErrored.getValues()).containsExactlyInAnyOrderElementsOf(first);

    failing.remove(a);
    final MappedResults<ArtifactSigner> recovered = load(dir1, a, b);
    assertThat(recovered.getErrorCount()).isZero();
    assertThat(recovered.getValues()).hasSize(2);
    final Set<ArtifactSigner> unchanged = new HashSet<>(first);
    unchanged.retainAll(recovered.getValues());
    assertThat(unchanged).hasSize(1);
  }

  @Test
  void failedFileWithoutPreviousLoadIsOnlyCounted() {
    failing.add(a);

    final MappedResults<ArtifactSigner> first = load(dir1, a, b);
    assertThat(first.getValues()).hasSize(1);
    assertThat(first.getErrorCount()).isEqualTo(1);

    loadedFiles.clear();
    load(dir1, a, b);
    assertThat(loadedFiles).containsExactly(a);
  }

  @Test
  void evictedSignerIsNotRetainedAfterSourceError() {
    final MappedResults<ArtifactSigner> first = load(dir1, a, b);
    assertThat(first.getValues()).hasSize(2);

    cache.evict(a.getFileName().toString());

    final MappedResults<ArtifactSigner> retained = cache.retainAllOnSourceError(dir1);
    assertThat(retained.getValues()).containsExactly(signerByFile.get(b));
    assertThat(retained.getErrorCount()).isEqualTo(1);
  }

  @Test
  void evictedSignerIsNotRetainedWhenItsFileFailsLater() throws IOException {
    load(dir1, a, b);
    cache.evict(a.getFileName().toString());

    failing.add(a);
    bumpModifiedTime(a);
    final MappedResults<ArtifactSigner> result = load(dir1, a, b);

    assertThat(result.getValues()).containsExactly(signerByFile.get(b));
    assertThat(result.getErrorCount()).isEqualTo(1);
  }

  @Test
  void unlistedFilesAreDropped() {
    load(dir1, a, b);

    final MappedResults<ArtifactSigner> onlyA = load(dir1, a);
    assertThat(onlyA.getValues()).hasSize(1);

    loadedFiles.clear();
    final MappedResults<ArtifactSigner> both = load(dir1, a, b);
    assertThat(both.getValues()).hasSize(2);
    assertThat(loadedFiles).containsExactly(b);
  }

  @Test
  void deletedFileIsDroppedEvenWhenAnotherFileFails() throws IOException {
    load(dir1, a, b);
    final ArtifactSigner signerOfB = signerByFile.get(b);

    Files.delete(a);
    failing.add(b);
    bumpModifiedTime(b);
    final MappedResults<ArtifactSigner> result = load(dir1, b);

    assertThat(result.getValues()).containsExactly(signerOfB);
    assertThat(result.getErrorCount()).isEqualTo(1);
  }

  @Test
  void retainAllOnSourceErrorReturnsPreviousSignersWithOneErrorAndKeepsCache() {
    final MappedResults<ArtifactSigner> first = load(dir1, a, b);

    final MappedResults<ArtifactSigner> retained = cache.retainAllOnSourceError(dir1);
    assertThat(retained.getValues()).containsExactlyInAnyOrderElementsOf(first.getValues());
    assertThat(retained.getErrorCount()).isEqualTo(1);

    assertThat(new KeystoreSignerCache().retainAllOnSourceError(dir1).getValues()).isEmpty();
    assertThat(new KeystoreSignerCache().retainAllOnSourceError(dir1).getErrorCount()).isEqualTo(1);

    loadedFiles.clear();
    final MappedResults<ArtifactSigner> next = load(dir1, a, b);
    assertThat(loadedFiles).isEmpty();
    assertThat(next.getValues()).containsExactlyInAnyOrderElementsOf(first.getValues());
  }

  @Test
  void directoriesAreIndependent() throws IOException {
    final Path c = Files.writeString(dir2.resolve("c.json"), "c");
    load(dir1, a);
    final MappedResults<ArtifactSigner> second = load(dir2, c);

    final MappedResults<ArtifactSigner> retained = cache.retainAllOnSourceError(dir2);
    assertThat(retained.getValues()).containsExactlyElementsOf(second.getValues());
  }
}
