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
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestExtractOpensslVersion(t *testing.T) {
	tests := []struct {
		name string
		buf  string
		want string
	}{
		{"1.1.1 patch release", "OpenSSL 1.1.1j 16 Feb 2021\x00", "OpenSSL 1.1.1j"},
		{"3.x release", "OpenSSL 3.2.0 23 Nov 2023", "OpenSSL 3.2.0"},
		{"3.6.3 release", "OpenSSL 3.6.3 24 Sep 2024", "OpenSSL 3.6.3"},
		{"surrounded by noise", "\x00\x01padding OpenSSL 3.0.13 30 Jan 2024 more\x00", "OpenSSL 3.0.13"},
		{"no version string", "this library says nothing useful", ""},
		{"BoringSSL", "BoringSSL", ""},
		{"empty buffer", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractOpensslVersion([]byte(tt.buf)); got != tt.want {
				t.Errorf("extractOpensslVersion(%q) = %q, want %q", tt.buf, got, tt.want)
			}
		})
	}
}

func TestLibcryptoCandidates(t *testing.T) {
	tests := []struct {
		name      string
		directory string
		needed    []string
		want      []string
	}{
		{
			name:      "needed name is preferred and not duplicated",
			directory: "/apex/com.android.app/lib64",
			needed:    []string{"libcrypto.so.3", "libssl.so", "libc.so"},
			want: []string{
				"/apex/com.android.app/lib64/libcrypto.so.3",
				"/apex/com.android.app/lib64/libcrypto.so",
			},
		},
		{
			name:      "unconventional needed name is kept",
			directory: "/data/app/lib",
			needed:    []string{"libcrypto.so.1.1"},
			want: []string{
				"/data/app/lib/libcrypto.so.1.1",
				"/data/app/lib/libcrypto.so.3",
				"/data/app/lib/libcrypto.so",
			},
		},
		{
			name:      "no needed entries falls back to conventional names",
			directory: "/usr/lib",
			needed:    nil,
			want: []string{
				"/usr/lib/libcrypto.so.3",
				"/usr/lib/libcrypto.so",
			},
		},
		{
			name:      "unrelated needed entries are ignored",
			directory: "/usr/lib",
			needed:    []string{"libc.so.6", "libm.so.6"},
			want: []string{
				"/usr/lib/libcrypto.so.3",
				"/usr/lib/libcrypto.so",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := libcryptoCandidates(tt.directory, tt.needed); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("libcryptoCandidates(%q, %v) = %v, want %v", tt.directory, tt.needed, got, tt.want)
			}
		})
	}
}

func TestVersionOfLibraryNotAnELF(t *testing.T) {
	dir := t.TempDir()
	notELF := filepath.Join(dir, "libssl.so")
	if err := os.WriteFile(notELF, []byte("not an ELF file"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if got := versionOfLibrary(notELF); got != "" {
		t.Errorf("versionOfLibrary(non-ELF) = %q, want empty (treated as BoringSSL)", got)
	}
}

func TestVersionOfLibraryMissingFile(t *testing.T) {
	if got := versionOfLibrary(filepath.Join(t.TempDir(), "libssl.so")); got != "" {
		t.Errorf("versionOfLibrary(missing) = %q, want empty", got)
	}
}
