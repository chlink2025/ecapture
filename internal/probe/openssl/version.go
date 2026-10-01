// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"path/filepath"
	"regexp"
	"strings"
)

// opensslVersionRe matches the "OpenSSL x.y.z" string embedded in the .rodata section of a
// library, e.g. "OpenSSL 1.1.1j" or "OpenSSL 3.2.0".
var opensslVersionRe = regexp.MustCompile(`(OpenSSL\s\d\.\d\.[0-9a-z]+)`)

// extractOpensslVersion returns the OpenSSL version string found in a chunk of a library's
// .rodata section, or an empty string when the chunk holds none.
func extractOpensslVersion(buf []byte) string {
	match := opensslVersionRe.Find(buf)
	if match == nil {
		return ""
	}
	return string(match)
}

// libcryptoCandidates returns the libcrypto paths to try, in order, for a library that lives
// in directory and lists needed among its DT_NEEDED entries. The entries whose name contains
// "libcrypto.so" come first, followed by the conventional names beside the library. Duplicate
// paths are dropped.
func libcryptoCandidates(directory string, needed []string) []string {
	var candidates []string
	seen := make(map[string]struct{})
	add := func(name string) {
		path := filepath.Join(directory, name)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		candidates = append(candidates, path)
	}

	for _, name := range needed {
		if strings.Contains(name, "libcrypto.so") {
			add(name)
		}
	}
	add("libcrypto.so.3")
	add("libcrypto.so")
	return candidates
}

// versionOfLibrary returns the OpenSSL version a library reports, asking its libcrypto when
// the library itself reports none.
//
// The library comes first, which is what covers an application that links OpenSSL
// statically into a library of its own and has no separate libcrypto to ask. Otherwise the
// libcrypto it loads is asked: by the name in its DT_NEEDED entries where that can be read,
// then by the conventional name beside it. A library that reports nothing in any of them is
// treated as BoringSSL, which is what Android's own copy of it does.
func versionOfLibrary(soPath string) string {
	if version, err := detectOpenssl(soPath); err == nil && version != "" {
		return version
	}

	needed, _ := getImpNeeded(soPath)
	for _, candidate := range libcryptoCandidates(filepath.Dir(soPath), needed) {
		if version, err := detectOpenssl(candidate); err == nil && version != "" {
			return version
		}
	}
	return ""
}
