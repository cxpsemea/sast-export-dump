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
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
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

// this function comes from the original sast-to-ast-export tool
// with some modifications
func CreateExportPackage(symmetricKey []byte, prefix, zipFile string, fileList []string) error { //nolint:gocritic
	exportFileName := prefix + zipFile
	// create zip
	exportFile, ioErr := os.Create(exportFileName)
	if ioErr != nil {
		return errors.Wrap(ioErr, "failed to create file for encrypted data")
	}
	defer func() {
		if closeErr := exportFile.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Msg("closing export file")
		}
	}()

	zipWriter := zip.NewWriter(exportFile)
	defer zipWriter.Close()

	// chain deflate and encryption and then deflate of the zip archive itself
	// the first deflate is needed to reduce the encrypted file size
	// otherwise if file is encrypted and then deflated, deflate won't be able to reduce the size
	// because of the chaoric bytes of encrypted data
	var err error
	for _, fileName := range fileList {
		err = func() error {
			// files are added to the tmp
			file, ferr := os.Open(path.Join("out", zipFile, fileName))
			if ferr != nil {
				return errors.Wrap(ferr, "failed to open file for zip")
			}
			defer file.Close()

			zipFileWriter, zerr := zipWriter.Create(fileName)
			if zerr != nil {
				return errors.Wrapf(zerr, "failed to open zip writer for file %s", fileName)
			}

			// create pipe (bytes written to pw go to pr)
			pr, pw := io.Pipe()
			// errChan needs to be buffered to not block the pipe
			errChan := make(chan error, 1)
			go func() {
				// operations with pipe writer need to be in a separate goroutine
				// writer needs to be closed for reader to stop "waiting" for new bytes
				defer pw.Close()
				// apply first DEFLATE to original content (which will come to pipe writer from file)
				// this will send DEFLATEd content down the pipe to the reader
				flateWriter, ferr := flate.NewWriter(pw, flate.DefaultCompression)
				if ferr != nil {
					errChan <- err
					return
				}
				defer flateWriter.Close()
				if _, err = io.Copy(flateWriter, file); err != nil {
					errChan <- err
					return
				}
				errChan <- nil
			}()
			// EncryptSymmetric will get the DEFLATEd content from pipe reader, encrypt it and send
			// to zipFileWriter, which will apply DEFLATE again and write bytes inside the zip archive
			err = Encrypt(pr, zipFileWriter, symmetricKey, symmetricKey)
			if err != nil {
				return errors.Wrap(err, "failed to encrypt data")
			}

			return <-errChan
		}()
		if err != nil {
			return err
		}
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

	exportDir := filepath.Dir(zipFile)
	filename := filepath.Base(zipFile)
	fmt.Printf("file is at: %v, file is %v\n", exportDir, filename)

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

	var fileList []string
	var idmapping map[string][]uint64 = make(map[string][]uint64)
	var namemapping map[string][]string = make(map[string][]string)

	var uniqueProjectNames map[string]uint64 = make(map[string]uint64)
	nameConflicts := false

	keyBytes, _ := base64.StdEncoding.DecodeString(string(key))

	fmt.Println("Zip file contents will be extracted to 'out' folder.")

	zipReader, err := zip.OpenReader(zipFile)
	if err != nil {
		fmt.Printf("Failed to open zip file %v: %s\n", zipFile, err)
		return
	}

	defer func(zipReader *zip.ReadCloser) {
		_ = zipReader.Close()
	}(zipReader)

	for _, f := range zipReader.File {
		path_pre := "out/" + filename + "/"
		path := filepath.Dir(path_pre + f.Name)
		err := os.MkdirAll(path, 0777)
		fileList = append(fileList, f.Name)
		if err != nil {
			fmt.Printf("Failed to create folder %v: %s\n", path, err)
		} else {
			fmt.Printf("Reading file: %v\n", f.Name)
			zr, err := zipReader.Open(f.Name)
			if err != nil {
				fmt.Printf("Error while opening file: %s\n", err)
			}
			bt, err := io.ReadAll(zr)
			if err != nil {
				fmt.Printf("Error while reading file: %s\n", err)
			}

			// decrypt zipped content
			encryptedFile := bytes.NewBuffer(bt)
			compressedFile := bytes.NewBuffer([]byte{})

			err = Decrypt(encryptedFile, compressedFile, keyBytes, keyBytes)
			if err != nil {
				fmt.Printf("Error while decrypting: %s\n", err)
			}
			// decompress decrypted content
			flateReader := flate.NewReader(compressedFile)
			plaintext, err := io.ReadAll(flateReader)
			if err != nil {
				fmt.Printf("Error while reading file: %s\n", err)
			}

			if f.Name == "projects.json" {
				var allProjects []map[string]interface{}
				json.Unmarshal(plaintext, &allProjects)

				for id := range allProjects {
					if prefix != "" {
						allProjects[id]["name"] = prefix + allProjects[id]["name"].(string)
					}

					_, exists := uniqueProjectNames[allProjects[id]["name"].(string)]
					if exists {
						newName := fmt.Sprintf("%v-%d", allProjects[id]["name"].(string), (uint64)(allProjects[id]["id"].(float64)))
						fmt.Printf(" - duplicate project name %v with id %d, will rename this one to: %v\n",
							allProjects[id]["name"].(string),
							(uint64)(allProjects[id]["id"].(float64)),
							newName,
						)
						allProjects[id]["name"] = newName

						uniqueProjectNames[newName] = (uint64)(allProjects[id]["id"].(float64))

						nameConflicts = true
					} else {
						// no conflict
						uniqueProjectNames[allProjects[id]["name"].(string)] = (uint64)(allProjects[id]["id"].(float64))
					}

					idmapping[application] = append(idmapping[application], (uint64)(allProjects[id]["id"].(float64)))
					namemapping[application] = append(namemapping[application], allProjects[id]["name"].(string))
				}

				if prefix != "" || nameConflicts {
					plaintext, _ = json.Marshal(allProjects)
				}
			}

			os.WriteFile(path_pre+f.Name, plaintext, 0777)

		}

	}

	if prefix == "" && nameConflicts {
		prefix = "unique-"
		fmt.Printf("There were duplicate project names in the input. A new zip file will be created named unique-%v\n", filename)
	}

	rawJson, _ := json.Marshal(idmapping)
	os.WriteFile(prefix+"project_id_mapping.json", rawJson, 0777)
	rawJson, _ = json.Marshal(namemapping)
	os.WriteFile(prefix+"project_name_mapping.json", rawJson, 0777)

	if prefix != "" {
		err := CreateExportPackage(keyBytes, prefix, filename, fileList)
		if err != nil {
			fmt.Printf("Error while re-encrypting: %s\n", err)
		} else {
			fmt.Println("Re-encrypted using the same key into new file: ", prefix+filename)
		}
	}
}
