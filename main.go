// aesctr
// Credits: https://github.com/Xeoncross/go-aesctr-with-hmac
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	bufferSize int  = 16 * 1024
	ivSize     int  = 16
	v1         byte = 0x1
	hmacSize        = sha512.Size
)

// ErrInvalidHMAC for authentication failure
var ErrInvalidHMAC = errors.New("invalid HMAC")

// Encrypt the stream using the given AES-CTR and SHA512-HMAC key
func Encrypt(in io.Reader, out io.Writer, keyAes, keyHmac []byte) (err error) {
	iv := make([]byte, ivSize)
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	AES, err := aes.NewCipher(keyAes)
	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(AES, iv)
	HMAC := hmac.New(sha512.New, keyHmac) // https://golang.org/pkg/crypto/hmac/#New

	// Version
	_, err = out.Write([]byte{v1})
	if err != nil {
		return
	}

	w := io.MultiWriter(out, HMAC)

	_, err = w.Write(iv)
	if err != nil {
		return
	}

	buf := make([]byte, bufferSize)
	for {
		var n int
		n, err = in.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		if n != 0 {
			outBuf := make([]byte, n)
			ctr.XORKeyStream(outBuf, buf[:n])
			_, err = w.Write(outBuf)
			if err != nil {
				return err
			}
		}

		if err == io.EOF {
			break
		}
	}

	_, err = out.Write(HMAC.Sum(nil))

	return err
}

// Decrypt the stream and verify HMAC using the given AES-CTR and SHA512-HMAC key
// Do not trust the out io.Writer contents until the function returns the result
// of validating the ending HMAC hash.
func Decrypt(in io.Reader, out io.Writer, keyAes, keyHmac []byte) (err error) {
	// Read version (up to 0-255)
	var version int8
	err = binary.Read(in, binary.LittleEndian, &version)
	if err != nil {
		return
	}

	iv := make([]byte, ivSize)
	_, err = io.ReadFull(in, iv)
	if err != nil {
		return
	}

	AES, err := aes.NewCipher(keyAes)
	if err != nil {
		return
	}

	ctr := cipher.NewCTR(AES, iv)
	h := hmac.New(sha512.New, keyHmac)
	h.Write(iv)
	mac := make([]byte, hmacSize)

	w := out

	buf := bufio.NewReaderSize(in, bufferSize)
	var limit int
	var b []byte
	for {
		b, err = buf.Peek(bufferSize)
		if err != nil && err != io.EOF {
			return
		}

		limit = len(b) - hmacSize

		// We reached the end
		if err == io.EOF {
			left := buf.Buffered()
			if left < hmacSize {
				return errors.New("not enough left")
			}

			copy(mac, b[left-hmacSize:left])

			if left == hmacSize {
				break
			}
		}

		h.Write(b[:limit])

		// We always leave at least hmacSize bytes left in the buffer
		// That way, our next Peek() might be EOF, but we will still have enough
		outBuf := make([]byte, int64(limit))
		_, err = buf.Read(b[:limit])
		if err != nil {
			return
		}
		ctr.XORKeyStream(outBuf, b[:limit])
		_, err = w.Write(outBuf)
		if err != nil {
			return
		}

		if err == io.EOF {
			break
		}
	}

	if !hmac.Equal(mac, h.Sum(nil)) {
		return ErrInvalidHMAC
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sast-export-dump.exe <path to zip> <encryption key> [optional: application name] [optional: project name prefix]")
		return
	}

	zipFile := os.Args[1]
	key := os.Args[2]

	application := "MyApp"
	if len(os.Args) >= 4 {
		application = os.Args[3]
	}
	fmt.Println("Will generate mapping.json files mapping the projects to the application named: ", application)
	prefix := ""
	if len(os.Args) >= 5 {
		prefix = os.Args[4]
		fmt.Println("Will update the Cx1 project names with the prefix: ", prefix)
	}

	var idmapping map[string][]uint64 = make(map[string][]uint64)
	var namemapping map[string][]string = make(map[string][]string)
	/*var Projects []struct {
		ID   uint64 `json:"id"`
		Name string `json:"name"`
	}*/

	keyBytes, _ := base64.StdEncoding.DecodeString(string(key))

	fmt.Println("Zip file contents will be extracted to 'out' folder.")

	zipReader, _ := zip.OpenReader(zipFile)
	defer func(zipReader *zip.ReadCloser) {
		_ = zipReader.Close()
	}(zipReader)

	for _, f := range zipReader.File {
		path_pre := "out/" + zipFile + "/"
		path := filepath.Dir(path_pre + f.Name)
		err := os.MkdirAll(path, 0777)
		if err != nil {
			fmt.Printf("Failed to create folder %v: %s", path, err)
		} else {
			zr, _ := zipReader.Open(f.Name)
			bt, _ := io.ReadAll(zr)

			// decrypt zipped content
			encryptedFile := bytes.NewBuffer(bt)
			compressedFile := bytes.NewBuffer([]byte{})

			_ = Decrypt(encryptedFile, compressedFile, keyBytes, keyBytes)
			// decompress decrypted content
			flateReader := flate.NewReader(compressedFile)
			plaintext, _ := io.ReadAll(flateReader)

			if f.Name == "projects.json" {
				var temp []map[string]interface{}
				json.Unmarshal(plaintext, &temp)

				for id, project := range temp {
					idmapping[application] = append(idmapping[application], (uint64)(project["id"].(float64)))
					namemapping[application] = append(namemapping[application], project["name"].(string))

					if prefix != "" {
						temp[id]["name"] = prefix + temp[id]["name"].(string)
					}
				}

				if prefix != "" {
					plaintext, _ = json.Marshal(temp)
				}
			}

			os.WriteFile(path_pre+f.Name, plaintext, 0777)

		}

	}

	/*for _, p := range Projects {
		idmapping[application] = append(idmapping[application], p.ID)
		namemapping[application] = append(namemapping[application], p.Name)
	}*/
	rawJson, _ := json.Marshal(idmapping)
	os.WriteFile("project_id_mapping.json", rawJson, 0777)
	rawJson, _ = json.Marshal(namemapping)
	os.WriteFile("project_name_mapping.json", rawJson, 0777)

}
