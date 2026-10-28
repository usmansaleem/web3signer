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
package tech.pegasys.web3signer.keystorage.hashicorp;

import tech.pegasys.web3signer.keystorage.common.TrustStoreLoader;
import tech.pegasys.web3signer.keystorage.hashicorp.config.TlsOptions;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Optional;
import javax.net.ssl.TrustManagerFactory;

import org.apache.tuweni.net.tls.TrustManagerFactories;

/** Create TrustManagerFactory based on Trust store type. */
public class TrustManagerFactoryProvider {

  public static TrustManagerFactory getTrustManagerFactory(final TlsOptions tlsOptions)
      throws GeneralSecurityException, IOException {
    final TrustManagerFactory trustManagerFactory;
    final TrustStoreType trustStoreType =
        tlsOptions
            .getTrustStoreType()
            .orElseThrow(
                () ->
                    new HashicorpException(
                        "Cannot create TrustManagerFactory from empty truststore type."));
    trustManagerFactory =
        switch (trustStoreType) {
          case JKS, PKCS12 ->
              buildFromKeystore(
                  tlsOptions.getTrustStorePath(),
                  tlsOptions.getTrustStorePassword(),
                  trustStoreType);
          case PEM ->
              TrustStoreLoader.createTrustManagerFactory(
                  tlsOptions.getTrustStorePath(), Optional.empty());
          default ->
              // Tuweni throws an NPE if the trustStorePath has no directory prefix, thus requiring
              // the use of absolutePath.
              TrustManagerFactories.allowlistServers(
                  tlsOptions.getTrustStorePath().toAbsolutePath(), true);
        };
    return trustManagerFactory;
  }

  private static TrustManagerFactory buildFromKeystore(
      final Path keystorePath, final String keystorePassword, final TrustStoreType keystoreType)
      throws GeneralSecurityException, IOException {
    // Load the keystore
    final KeyStore keyStore = KeyStore.getInstance(keystoreType.name());
    try (final FileInputStream fis = new FileInputStream(keystorePath.toFile())) {
      keyStore.load(fis, keystorePassword.toCharArray());
    }

    // Initialize the TrustManagerFactory with the keystore
    final TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(keyStore);

    return trustManagerFactory;
  }
}
