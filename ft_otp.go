package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"
	"time"
)

const periodicity = 30
const numDig = 6
const saveKey = 1
const genPass = 2
const tenPowSix = 1000000

var b = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func generatePass(decryptedKey []byte) {
	timeInt64 := time.Now().Unix() / periodicity
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeInt64))

	var hasher hash.Hash = hmac.New(sha1.New, decryptedKey)
	hasher.Write(timeBytes)

	var hashedBytesTimeKey []byte = hasher.Sum(nil)
	lastFourBits := hashedBytesTimeKey[19] & 0xf
	binCode := (int(hashedBytesTimeKey[lastFourBits]&0x7f)<<24 | int(hashedBytesTimeKey[lastFourBits+1])<<16 |
		int(hashedBytesTimeKey[lastFourBits+2])<<8 | int(hashedBytesTimeKey[lastFourBits+3])) % tenPowSix
	fmt.Printf("%06d", binCode)
}

func decryptKey(fileName string) ([]byte, error) {
	encryptedKey, errEncKey := os.ReadFile(fileName)
	myKey, errMyKey := os.ReadFile("myKey.key")
	if errEncKey != nil || errMyKey != nil {
		return nil, errEncKey
	}

	block, err := aes.NewCipher(myKey)
	if err != nil {
		return nil, err
	}

	encrypter := cipher.NewCFBDecrypter(block, b)
	decryptedKey := make([]byte, len(encryptedKey))
	encrypter.XORKeyStream(decryptedKey, encryptedKey)

	return decryptedKey, nil
}

func parseHex(undecKey []byte) ([]byte, error) {
	decodedKey := make([]byte, hex.DecodedLen(len(undecKey)))
	numBytes, err := hex.Decode(decodedKey, undecKey)
	if err != nil || numBytes == 0 {
		return nil, err
	}
	return decodedKey, nil
}

func encryptKey(fileName string) error {
	key, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}

	if len(key) < 64 {
		return errors.New("error: key must be 64 hexadecimal characters.")
	}

	decodedKey, err := parseHex(key)
	if err != nil {
		return err
	}

	myKey := make([]byte, 32)
	_, err = rand.Read(myKey)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(myKey)
	if err != nil {
		return err
	}

	encrypter := cipher.NewCFBEncrypter(block, b)
	encryptedKey := make([]byte, len(decodedKey))
	encrypter.XORKeyStream(encryptedKey, decodedKey)

	otpKeyWriter, err := os.Create("ft_otp.key")
	if err != nil {
		return err
	}
	if _, err = otpKeyWriter.Write(encryptedKey); err != nil {
		return err
	}
	defer otpKeyWriter.Close()

	myKeyWriter, err := os.Create("myKey.key")
	if err != nil {
		return err
	}
	if _, err = myKeyWriter.Write(myKey); err != nil {
		return err
	}
	defer myKeyWriter.Close()
	fmt.Println("Key was successfully saved in ft_otp.key.")
	return nil
}

func readArgs() (string, int, error) {
	args := os.Args
	if len(args) != 3 {
		return "", 0, errors.New("Wrong number of args")
	}
	fileName := args[2]
	if args[1] == "-g" && strings.HasSuffix(fileName, ".hex") {
		return fileName, saveKey, nil
	} else if args[1] == "-k" && strings.HasSuffix(fileName, ".key") {
		return fileName, genPass, nil
	} else {
		return fileName, 0, errors.New("Wrong args")
	}
}

func main() {
	fileName, act, err := readArgs()
	if err != nil {
		fmt.Println(err)
	}
	if act == saveKey {
		if err := encryptKey(fileName); err != nil {
			fmt.Println(err)
		}
	} else if act == genPass {
		decryptedKey, err := decryptKey(fileName)
		if err != nil {
			fmt.Println(err)
			return
		}
		generatePass(decryptedKey)
	}
}
