package utils

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// 生成 MD5 摘要
func MD5Hash(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))) // 转换为大写
}

// 生成 HMAC-SHA1 签名
func GenerateHMACSHA1(secret, data string) []byte {
	h := hmac.New(sha1.New, []byte(secret))
	h.Write([]byte(data))
	return h.Sum(nil)
}

// 生成签名的函数
func GenerateSignature(secret, method, uri, clientID, timestamp, body string, queryParam map[string][]string) (string, error) {
	// 计算 Canonical Body
	bodyMD5 := MD5Hash(body)

	// 构建 Canonical Headers
	canonicalHeaders := fmt.Sprintf("x-drc-client:%s\nx-drc-timestamp:%s", strings.ToLower(clientID), strings.TrimSpace(timestamp))

	// 构建 Canonical Query String
	canonicalQueryString := BuildCanonicalQueryString(queryParam)

	// 构建 Canonical 字符串
	canonicalString := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", method, uri, canonicalQueryString, canonicalHeaders, bodyMD5)

	// 生成签名
	signature := GenerateHMACSHA1(secret, canonicalString)

	// 返回 Base64 编码后的签名
	return base64.StdEncoding.EncodeToString(signature), nil
}

// 构建 Canonical Query String
func BuildCanonicalQueryString(queryParam map[string][]string) string {
	// 提取并排序键
	keys := make([]string, 0, len(queryParam))
	for key := range queryParam {
		keys = append(keys, key)
	}
	sort.Strings(keys) // 按键排序

	// 构建排序后的键值对
	var queryParts []string
	for _, key := range keys {
		values := queryParam[key]
		sort.Strings(values) // 按值排序（如果有多个值）
		for _, value := range values {
			queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(value)))
		}
	}

	// 将键值对拼接为字符串
	return strings.Join(queryParts, "&")
}
