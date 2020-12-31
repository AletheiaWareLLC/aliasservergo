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
	"aletheiaware.com/aliasgo"
	"aletheiaware.com/bcgo"
	"aletheiaware.com/cryptogo"
	"aletheiaware.com/netgo"
	"encoding/base64"
	"github.com/golang/protobuf/proto"
	"html/template"
	"log"
	"net/http"
	"os"
)

func AliasHandler(aliases *bcgo.Channel, cache bcgo.Cache, template *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			alias := netgo.GetQueryParameter(r.URL.Query(), "alias")
			log.Println("Alias", alias)

			data := struct {
				Alias     string
				Timestamp string
				PublicKey string
			}{}
			if alias != "" {
				r, a, err := aliasgo.GetRecord(aliases, cache, nil, alias)
				if err != nil {
					log.Println(err)
					return
				}
				data.Alias = alias
				data.Timestamp = bcgo.TimestampToString(r.Timestamp)
				data.PublicKey = base64.RawURLEncoding.EncodeToString(a.PublicKey)
			}
			if err := template.Execute(w, data); err != nil {
				log.Println(err)
				return
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}

func AliasListHandler(aliases *bcgo.Channel, cache bcgo.Cache, template *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path, r.Header)
		switch r.Method {
		case "GET":
			type TemplateAlias struct {
				Alias     string
				Timestamp string
				Hash      string
			}
			as := make([]TemplateAlias, 0)
			if err := bcgo.Iterate(aliases.Name, aliases.Head, nil, cache, nil, func(h []byte, b *bcgo.Block) error {
				for _, entry := range b.Entry {
					record := entry.Record
					a := &aliasgo.Alias{}
					err := proto.Unmarshal(record.Payload, a)
					if err != nil {
						return err
					}
					as = append(as, TemplateAlias{
						Alias:     a.Alias,
						Timestamp: bcgo.TimestampToString(record.Timestamp),
						Hash:      base64.RawURLEncoding.EncodeToString(h),
					})
				}
				return nil
			}); err != nil {
				log.Println(err)
				return
			}
			data := struct {
				Alias []TemplateAlias
			}{
				Alias: as,
			}
			if err := template.Execute(w, data); err != nil {
				log.Println(err)
				return
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}

func AliasRegistrationHandler(aliases *bcgo.Channel, node *bcgo.Node, threshold uint64, listener bcgo.MiningListener, template *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.RemoteAddr, r.Proto, r.Method, r.Host, r.URL.Path)
		switch r.Method {
		case "GET":
			alias := netgo.GetQueryParameter(r.URL.Query(), "alias")
			publicKey := netgo.GetQueryParameter(r.URL.Query(), "publicKey")
			log.Println("Alias", alias)
			log.Println("PublicKey", publicKey)

			data := struct {
				Alias     string
				PublicKey string
			}{
				Alias:     alias,
				PublicKey: publicKey,
			}
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

				if err := aliasgo.ValidateAlias(alias[0]); err != nil {
					log.Println(err)
					return
				}

				if err := aliases.Pull(node.Cache, node.Network); err != nil {
					log.Println(err)
				}

				if err := aliasgo.UniqueAlias(aliases, node.Cache, node.Network, alias[0]); err != nil {
					log.Println(err)
					return
				}

				pubKey, err := base64.RawURLEncoding.DecodeString(publicKey[0])
				if err != nil {
					log.Println(err)
					return
				}

				pubFormatValue, ok := cryptogo.PublicKeyFormat_value[publicKeyFormat[0]]
				if !ok {
					log.Println("Unrecognized Public Key Format")
					return
				}
				pubFormat := cryptogo.PublicKeyFormat(pubFormatValue)

				sig, err := base64.RawURLEncoding.DecodeString(signature[0])
				if err != nil {
					log.Println(err)
					return
				}

				sigAlgValue, ok := cryptogo.SignatureAlgorithm_value[signatureAlgorithm[0]]
				if !ok {
					log.Println("Unrecognized Signature Algorithm")
					return
				}
				sigAlg := cryptogo.SignatureAlgorithm(sigAlgValue)

				publicKey, err := cryptogo.ParseRSAPublicKey(pubKey, pubFormat)
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

				if err := cryptogo.VerifySignature(publicKey, cryptogo.Hash(data), sig, sigAlg); err != nil {
					log.Println(err)
					return
				}

				record := &bcgo.Record{
					Timestamp:           bcgo.Timestamp(),
					Creator:             alias[0],
					Payload:             data,
					EncryptionAlgorithm: cryptogo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION,
					Signature:           sig,
					SignatureAlgorithm:  sigAlg,
				}
				if l, ok := os.LookupEnv(bcgo.LIVE_FLAG); ok {
					record.Meta = map[string]string{
						bcgo.LIVE_FLAG: l,
					}
				}

				// TODO should this write to cache, or just mine the blockentry directly?
				// Could cause issues where alias is registered elsewhere in race-condition with this node, but this record is sitting in the cache waiting to get mined
				reference, err := bcgo.WriteRecord(aliasgo.ALIAS, node.Cache, record)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Wrote Record", base64.RawURLEncoding.EncodeToString(reference.RecordHash))

				// Mine record into blockchain
				hash, _, err := node.Mine(aliases, threshold, listener)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Mined Alias", base64.RawURLEncoding.EncodeToString(hash))

				// Push update to peers
				if err := aliases.Push(node.Cache, node.Network); err != nil {
					log.Println(err)
				}
			}
		default:
			log.Println("Unsupported method", r.Method)
		}
	}
}
