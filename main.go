// Copyright 2022 pschou (https://github.com/pschou)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	rpm "github.com/pschou/go-rpm"
	"golang.org/x/crypto/openpgp"
)

var version string

func main() {
	flag.Usage = func() {
		_, f := path.Split(os.Args[0])
		fmt.Fprintf(os.Stderr, "rpm-verify,  Version: %s (https://github.com/pschou/rpm-verify)\n\n"+
			"Usage: %s [options] test.rpm\n\n", version, f)
		flag.PrintDefaults()
	}

	log.SetFlags(0)
	log.SetPrefix("rpm-verify: ")
	keyringFile := flag.String("keyring", "keys/", "Use keyring for verifying, keyring.gpg or keys/ directory")

	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("Input file to test needed")
		os.Exit(1)
	}

	var keyring openpgp.EntityList

	var err error
	if _, ok := isDirectory(*keyringFile); ok {
		//keyring = openpgp.EntityList{}
		for _, file := range getFiles(*keyringFile, ".gpg") {
			//fmt.Println("loading key", file)
			gpgFile, err := os.ReadFile(file)
			if err != nil {
				log.Fatal("Error reading keyring file", err)
			}
			fileKeys, err := loadKeys(gpgFile)
			if err != nil {
				log.Fatal("Error loading keyring file", err)
			}
			//fmt.Println("  found", len(fileKeys), "keys")
			keyring = append(keyring, fileKeys...)
		}
	} else {
		gpgFile, err := os.ReadFile(*keyringFile)
		if err != nil {
			log.Fatal("Error reading keyring file", err)
		}
		keyring, err = loadKeys(gpgFile)
		if err != nil {
			log.Fatal("Error loading keyring file", err)
		}
	}
	if len(keyring) == 0 {
		log.Fatal("no keys loaded")
	}

	fmt.Println("opening:", flag.Arg(0))

	fi, err := os.Open(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	r := rpm.NewReader(fi)

	var lead *rpm.Lead
	if lead, err = r.Lead(); err != nil {
		log.Fatal(err)
	}

	if lead.SignatureType != 5 {
		fmt.Println("Unknown signature type:", lead.SignatureType)
		os.Exit(1)
	}

	var (
		hdr  *rpm.Header
		hdrs []*rpm.Header
	)

	var pgpData []byte

	for i := 0; i < 1; i++ {
		hdr, err = r.Next()
		if err != nil {
			fmt.Println("error parsing header:", err)
			break
		}
		for _, t := range hdr.Tags {
			if t.Count <= 2 {
				continue
			}
			switch t.Tag {
			case rpm.RPMSIGTAG_PGP:
				pgpData, _ = t.Bytes()
				//case rpm.RPMTAG_RSAHEADER:
				//	rsaData, _ = t.Bytes()
			}
		}
		hdrs = append(hdrs, hdr)
	}

	align(fi)

	signer, err := openpgp.CheckDetachedSignature(keyring, fi, bytes.NewReader(pgpData))
	if signer.PrimaryKey != nil {
		for k, _ := range signer.Identities {
			fmt.Printf("Signed by: %s (%02x)\n", k, signer.PrimaryKey.KeyId)
			os.Exit(0)
		}
	}
	os.Exit(1)
}

// isDirectory determines if a file represented
// by `path` is a directory or not
func isDirectory(path string) (exist bool, isdir bool) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, false
	}
	return true, fileInfo.IsDir()
}

func getFiles(walkdir, suffix string) []string {
	ret := []string{}
	err := filepath.Walk(walkdir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Println(err)
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, suffix) {
				ret = append(ret, path)
			}
			return nil
		})
	if err != nil {
		log.Fatal(err)
	}
	return ret
}

func align(r *os.File) error {
	offset, _ := r.Seek(0, io.SeekCurrent)
	i := (offset + 0x7) &^ 0x7
	_, err := r.Seek(i, io.SeekStart)
	return err
}
