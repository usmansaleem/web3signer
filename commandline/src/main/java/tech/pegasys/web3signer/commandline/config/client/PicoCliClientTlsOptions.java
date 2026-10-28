/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.web3signer.commandline.config.client;

import static tech.pegasys.web3signer.commandline.DefaultCommandValues.BOOL_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.FILE_FORMAT_HELP;

import tech.pegasys.web3signer.core.config.KeyStoreOptions;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;
import tech.pegasys.web3signer.core.config.client.ClientTlsOptions;

import java.nio.file.Path;
import java.util.Optional;

import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

public class PicoCliClientTlsOptions implements ClientTlsOptions {
  @SuppressWarnings("UnusedVariable")
  @Option(
      names = "--downstream-http-tls-enabled",
      description = "Flag to enable TLS connection to web3 provider. Defaults to disabled.",
      paramLabel = BOOL_FORMAT_HELP,
      arity = "0..1")
  private boolean tlsEnabled = false;

  @Mixin private PicoCliKeyStoreOptions keyStoreOptions;

  @Option(
      names = "--downstream-http-tls-known-servers-file",
      description =
          "DEPRECATED: use --downstream-http-tls-truststore-file instead; this option will be "
              + "removed in a future release. Path to a file containing the hostname, port and "
              + "certificate fingerprints of web3 providers to trust.",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private Path knownServersFile;

  @Option(
      names = "--downstream-http-tls-truststore-file",
      description =
          "Path to a truststore containing the certificates, or issuing CA certificates, of web3 "
              + "providers to trust. PKCS#12 (preferred), JKS or PEM; the format is detected from "
              + "the file content. Replaces the system's default CAs; if not set, the system's "
              + "default CAs are used.",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private Path trustStoreFile;

  @Option(
      names = "--downstream-http-tls-truststore-password-file",
      description =
          "Path to a file containing the password used to open the truststore. Required for "
              + "PKCS#12 and JKS truststores, not used for PEM.",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private Path trustStorePasswordFile;

  @Option(
      names = "--downstream-http-tls-ca-auth-enabled",
      description =
          "DEPRECATED: only applies to the deprecated --downstream-http-tls-known-servers-file and "
              + "will be removed with it. If set, will use the system's CA to validate received "
              + "server certificates. Defaults to enabled.",
      arity = "1")
  private Boolean caAuthEnabled = null;

  @Override
  public Optional<KeyStoreOptions> getKeyStoreOptions() {
    if (keyStoreOptions.getKeyStoreFile() == null && keyStoreOptions.getPasswordFile() == null) {
      return Optional.empty();
    }
    return Optional.of(keyStoreOptions);
  }

  @Override
  public boolean isCaAuthEnabled() {
    return caAuthEnabled == null || caAuthEnabled;
  }

  public boolean isCaAuthEnabledSpecified() {
    return caAuthEnabled != null;
  }

  @Override
  public Optional<Path> getKnownServersFile() {
    return Optional.ofNullable(knownServersFile);
  }

  @Override
  public Optional<TrustStoreOptions> getTrustStoreOptions() {
    if (trustStoreFile == null) {
      return Optional.empty();
    }
    return Optional.of(
        new TrustStoreOptions(trustStoreFile, Optional.ofNullable(trustStorePasswordFile)));
  }

  public Path getTrustStorePasswordFile() {
    return trustStorePasswordFile;
  }

  public boolean isTlsEnabled() {
    return tlsEnabled;
  }
}
