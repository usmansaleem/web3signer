/*
 * Copyright 2018 ConsenSys AG.
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
package tech.pegasys.web3signer.core.service.jsonrpc.response;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"jsonrpc", "id", "error"})
public class JsonRpcErrorResponse implements JsonRpcResponse {

  private final Object id;
  private final JsonRpcError error;

  @JsonCreator
  public JsonRpcErrorResponse(
      @JsonProperty("id") final Object id, @JsonProperty("error") final JsonRpcError error) {
    this.id = id;
    this.error = error;
  }

  public JsonRpcErrorResponse(final JsonRpcError error) {
    this(null, error);
  }

  @JsonGetter("id")
  public Object getId() {
    return id;
  }

  @JsonGetter("error")
  public JsonRpcError getError() {
    return error;
  }

  @Override
  @JsonIgnore
  public JsonRpcResponseType getType() {
    return JsonRpcResponseType.ERROR;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    final JsonRpcErrorResponse that = (JsonRpcErrorResponse) o;
    return Objects.equals(id, that.id) && error == that.error;
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, error);
  }
}
