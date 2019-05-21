/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aliasservergo_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/aliasservergo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	TEMPLATE = "Alias:{{ .Alias }} Timestamp:{{ .Timestamp }} PublicKey:{{ .PublicKey }}"
)

func TestAliasHandler(t *testing.T) {
	t.Run("GETNotExists", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "/alias?alias=Alice", nil)
		response := httptest.NewRecorder()

		cache := bcgo.NewMemoryCache(10)
		aliases := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		temp, err := template.New("AliasTest").Parse(TEMPLATE)
		testinggo.AssertNoError(t, err)
		handler := aliasservergo.AliasHandler(aliases, cache, temp)
		handler(response, request)

		expected := ""
		got := response.Body.String()

		if got != expected {
			t.Errorf("Incorrect response; expected '%s', got '%s'", expected, got)
		}
	})
	t.Run("GETExists", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "/alias?alias=Alice", nil)
		response := httptest.NewRecorder()

		key, err := rsa.GenerateKey(rand.Reader, 4096)
		testinggo.AssertNoError(t, err)
		record, err := aliasgo.CreateAliasRecord("Alice", key)
		testinggo.AssertNoError(t, err)
		recordHash, err := bcgo.HashProtobuf(record)
		testinggo.AssertNoError(t, err)
		block := &bcgo.Block{
			Timestamp:   record.Timestamp,
			ChannelName: "Alias",
			Entry: []*bcgo.BlockEntry{
				&bcgo.BlockEntry{
					Record:     record,
					RecordHash: recordHash,
				},
			},
		}
		blockHash, err := bcgo.HashProtobuf(block)
		testinggo.AssertNoError(t, err)
		cache := bcgo.NewMemoryCache(10)
		cache.PutHead("Alias", &bcgo.Reference{
			Timestamp:   block.Timestamp,
			ChannelName: block.ChannelName,
			BlockHash:   blockHash,
		})
		cache.PutBlock(blockHash, block)
		aliases := aliasgo.OpenAndLoadAliasChannel(cache, nil)
		temp, err := template.New("AliasTest").Parse(TEMPLATE)
		testinggo.AssertNoError(t, err)
		handler := aliasservergo.AliasHandler(aliases, cache, temp)
		handler(response, request)

		publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&key.PublicKey)
		testinggo.AssertNoError(t, err)
		expected := "Alias:Alice Timestamp:" + bcgo.TimestampToString(block.Timestamp) + " PublicKey:" + base64.RawURLEncoding.EncodeToString(publicKeyBytes)
		got := response.Body.String()

		if got != expected {
			t.Errorf("Incorrect response; expected '%s', got '%s'", expected, got)
		}
	})
}

func TestAliasRegistrationHandler(t *testing.T) {
	t.Run("GETEmpty", func(t *testing.T) {
		// TODO
	})
	t.Run("GETParams", func(t *testing.T) {
		// TODO
	})
	t.Run("POSTEmpty", func(t *testing.T) {
		// TODO
	})
	t.Run("POSTNotUnique", func(t *testing.T) {
		// TODO
	})
	t.Run("POSTInvalidSignature", func(t *testing.T) {
		// TODO
	})
	t.Run("POSTUnique", func(t *testing.T) {
		// TODO
	})
}
