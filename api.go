package kms

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var base64Coder = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

func VerifyLicense(_license string, _appKey string, _appSecret string, _deviceCode string) (int, error) {
	lines := strings.Split(_license, "\n")
	if len(lines) < 16 {
		return 1, errors.New("invalid license")
	}

	if "key:" != lines[0] ||
		"secret:" != lines[2] ||
		"code:" != lines[4] ||
		"timestamp:" != lines[6] ||
		"expiry:" != lines[8] ||
		"storage:" != lines[10] ||
		"cer:" != lines[12] ||
		"sig:" != lines[14] {
		return 2, errors.New("missing some fields")
	}

	passwd := toPassword(lines[1], lines[3])
	//take payload
	payload := fmt.Sprintf("key:\n%s\nsecret:\n%s\ncode:\n%s\ntimestamp:\n%s\nexpiry:\n%s\nstorage:\n%s\ncer:\n%s",
		lines[1], lines[3], lines[5], lines[7], lines[9], lines[11], lines[13])
	payload_ciphertext, err := aesEncrypt([]byte(payload), []byte(passwd))
	payload_md5 := toMD5(payload_ciphertext)
	//take cer
	cer_ciphertext, err := base64Coder.DecodeString(lines[13])
	if nil != err {
		return 3, err
	}
	cer, err := aesDecrypt(cer_ciphertext, []byte(passwd))
	if nil != err {
		return 4, err
	}

	//take sig
	sig_ciphertext, err := base64Coder.DecodeString(lines[15])
	if nil != err {
		return 5, err
	}

	err = rsaVerify(cer, []byte(payload_md5), []byte(sig_ciphertext))
	if nil != err {
		return 6, err
	}

	timestamp, err := strconv.ParseInt(lines[7], 10, 64)
	if nil != err {
		return 7, err
	}

	expiry, err := strconv.ParseInt(lines[9], 10, 64)
	if nil != err {
		return 8, err
	}

	if _appKey != lines[1] {
		return 11, errors.New("appname is not matched")
	}
	if _appSecret != lines[3] {
		return 12, errors.New("appsecret is not matched")
	}
	if _deviceCode != lines[5] {
		return 13, errors.New("devicecode is not matched")
	}

	if expiry != 0 {
		now := time.Now().Unix()
		if now-timestamp > expiry*24*60*60 {
			return 14, errors.New("expiry")
		}
	}

	return 0, nil
}

func int64tobytes(_value int64) []byte {
	buf := make([]byte, 8)
	buf[0] = byte(_value)
	buf[1] = byte(_value >> 8)
	buf[2] = byte(_value >> 16)
	buf[3] = byte(_value >> 24)
	buf[4] = byte(_value >> 32)
	buf[5] = byte(_value >> 40)
	buf[6] = byte(_value >> 48)
	buf[7] = byte(_value >> 56)
	return buf
}

func bytestoint64(_value []byte) int64 {
	val := int64(0)
	val |= int64(_value[0])
	val |= int64(_value[1]) << 8
	val |= int64(_value[2]) << 16
	val |= int64(_value[3]) << 24
	val |= int64(_value[4]) << 32
	val |= int64(_value[5]) << 40
	val |= int64(_value[6]) << 48
	val |= int64(_value[7]) << 56
	return val
}

func int32tobytes(_value int32) []byte {
	buf := make([]byte, 4)
	buf[0] = byte(_value)
	buf[1] = byte(_value >> 8)
	buf[2] = byte(_value >> 16)
	buf[3] = byte(_value >> 24)
	return buf
}

func bytestoint32(_value []byte) int32 {
	val := int32(0)
	val |= int32(_value[0])
	val |= int32(_value[1]) << 8
	val |= int32(_value[2]) << 16
	val |= int32(_value[3]) << 24
	return val
}

func toMD5(_val []byte) string {
	hash := md5.New()
	hash.Write(_val)
	return hex.EncodeToString(hash.Sum(nil))
}

func toPassword(_appKey string, _appSecret string) string {
	hash := md5.New()
	hash.Write([]byte(_appKey + "*!@#omo#@!*" + _appSecret))
	pwd := hex.EncodeToString(hash.Sum(nil))
	return strings.ToUpper(pwd)
}
