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

package aliasservergo

import (
	"encoding/base64"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/bcnetgo"
	"github.com/golang/protobuf/proto"
	"html/template"
	"log"
	"net/http"
	"time"
)

func AliasHandler(aliases *aliasgo.AliasChannel, cache bcgo.Cache, network bcgo.Network, template *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			alias := bcnetgo.GetQueryParameter(r.URL.Query(), "alias")
			log.Println("Alias", alias)

			r, a, err := aliases.GetRecord(cache, alias)
			if err != nil {
				log.Println(err)
				return
			}
			data := struct {
				Alias     string
				Timestamp string
				PublicKey string
			}{
				Alias:     alias,
				Timestamp: bcgo.TimestampToString(r.Timestamp),
				PublicKey: base64.RawURLEncoding.EncodeToString(a.PublicKey),
			}
			log.Println("Data", data)
			if err := template.Execute(w, data); err != nil {
				log.Println(err)
				return
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}

func AliasRegistrationHandler(aliases *aliasgo.AliasChannel, node *bcgo.Node, listener bcgo.MiningListener, template *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			alias := bcnetgo.GetQueryParameter(r.URL.Query(), "alias")
			publicKey := bcnetgo.GetQueryParameter(r.URL.Query(), "publicKey")
			log.Println("Alias", alias)
			log.Println("PublicKey", publicKey)

			data := struct {
				Alias     string
				PublicKey string
			}{
				Alias:     alias,
				PublicKey: publicKey,
			}
			log.Println("Data", data)
			if err := template.Execute(w, data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			r.ParseForm()
			log.Println("Request", r)
			alias := r.Form["alias"]
			log.Println("Alias", alias)
			publicKey := r.Form["publicKey"]
			log.Println("PublicKey", publicKey)
			publicKeyFormat := r.Form["publicKeyFormat"]
			log.Println("PublicKeyFormat", publicKeyFormat)
			signature := r.Form["signature"]
			log.Println("Signature", signature)
			signatureAlgorithm := r.Form["signatureAlgorithm"]
			log.Println("SignatureAlgorithm", signatureAlgorithm)

			if len(alias) > 0 && len(publicKey) > 0 && len(publicKeyFormat) > 0 && len(signature) > 0 && len(signatureAlgorithm) > 0 {
				if alias[0] == "" {
					log.Println("Empty Alias")
					return
				}

				if err := aliases.UniqueAlias(node.Cache, alias[0]); err != nil {
					log.Println(err)
					return
				}

				pubKey, err := base64.RawURLEncoding.DecodeString(publicKey[0])
				if err != nil {
					log.Println(err)
					return
				}

				pubFormatValue, ok := bcgo.PublicKeyFormat_value[publicKeyFormat[0]]
				if !ok {
					log.Println("Unrecognized Public Key Format")
					return
				}
				pubFormat := bcgo.PublicKeyFormat(pubFormatValue)

				sig, err := base64.RawURLEncoding.DecodeString(signature[0])
				if err != nil {
					log.Println(err)
					return
				}

				sigAlgValue, ok := bcgo.SignatureAlgorithm_value[signatureAlgorithm[0]]
				if !ok {
					log.Println("Unrecognized Signature Algorithm")
					return
				}
				sigAlg := bcgo.SignatureAlgorithm(sigAlgValue)

				publicKey, err := bcgo.ParseRSAPublicKey(pubKey, pubFormat)
				if err != nil {
					log.Println(err)
					return
				}

				a := &aliasgo.Alias{
					Alias:        alias[0],
					PublicKey:    pubKey,
					PublicFormat: pubFormat,
				}

				data, err := proto.Marshal(a)
				if err != nil {
					log.Println(err)
					return
				}

				if err := bcgo.VerifySignature(publicKey, bcgo.Hash(data), sig, sigAlg); err != nil {
					log.Println(err)
					return
				}

				record := &bcgo.Record{
					Timestamp:           uint64(time.Now().UnixNano()),
					Creator:             alias[0],
					Payload:             data,
					EncryptionAlgorithm: bcgo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION,
					Signature:           sig,
					SignatureAlgorithm:  sigAlg,
				}

				reference, err := bcgo.WriteRecord(aliases.GetName(), node.Cache, record)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Created Record", base64.RawURLEncoding.EncodeToString(reference.RecordHash))

				// Mine record into blockchain
				hash, _, err := node.Mine(aliases, listener)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Mined Alias", base64.RawURLEncoding.EncodeToString(hash))

				// Push update to peers
				if err := bcgo.Push(aliases, node.Cache, node.Network); err != nil {
					log.Println(err)
					return
				}
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}
