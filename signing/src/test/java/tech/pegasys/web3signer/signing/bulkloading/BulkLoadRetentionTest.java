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

import java.util.List;

import org.junit.jupiter.api.Test;

class BulkLoadRetentionTest {

  private final BulkLoadRetention retention = new BulkLoadRetention("test vault");
  private final ArtifactSigner key1 = signer("k1");
  private final ArtifactSigner key2 = signer("k2");

  private static ArtifactSigner signer(final String identifier) {
    final ArtifactSigner signer = mock(ArtifactSigner.class);
    when(signer.getIdentifier()).thenReturn(identifier);
    return signer;
  }

  @Test
  void keysMissingFromErroredResultAreRetained() {
    retention.retainMissingOnError(MappedResults.newInstance(List.of(key1, key2), 0));

    final MappedResults<ArtifactSigner> result =
        retention.retainMissingOnError(MappedResults.newInstance(List.of(key2), 1));

    assertThat(result.getValues()).containsExactlyInAnyOrder(key1, key2);
    assertThat(result.getErrorCount()).isEqualTo(1);
  }

  @Test
  void errorFreeResultDropsKeysRetainedByEarlierErroredResult() {
    retention.retainMissingOnError(MappedResults.newInstance(List.of(key1, key2), 0));
    retention.retainMissingOnError(MappedResults.newInstance(List.of(key2), 1));

    final MappedResults<ArtifactSigner> result =
        retention.retainMissingOnError(MappedResults.newInstance(List.of(key2), 0));

    assertThat(result.getValues()).containsExactly(key2);
    assertThat(result.getErrorCount()).isZero();
  }

  @Test
  void erroredResultOnFreshInstanceIsUnchanged() {
    final MappedResults<ArtifactSigner> result =
        retention.retainMissingOnError(MappedResults.newInstance(List.of(key2), 1));

    assertThat(result.getValues()).containsExactly(key2);
    assertThat(result.getErrorCount()).isEqualTo(1);
  }

  @Test
  void keyPresentInErroredResultIsNotDuplicated() {
    retention.retainMissingOnError(MappedResults.newInstance(List.of(key1), 0));

    final MappedResults<ArtifactSigner> result =
        retention.retainMissingOnError(MappedResults.newInstance(List.of(key1, key2), 2));

    assertThat(result.getValues()).containsExactlyInAnyOrder(key1, key2);
  }
}
