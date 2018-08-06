package aws

import (
        "fmt"
        "hash"
        "crypto/hmac"
        "crypto/sha256"
        "sort"
	"strings"
        "net/url"
)

const (
        Algorithm string = "AWS4-HMAC-SHA256"
        
        ISO8601DateEndIndex int = 8

        Terminal string = "aws4_request"
)

type RequestParams struct {
        Service     string
        Region      string
        Method      string
        URL         string
        Headers     map[string]string
        Body        []byte
        AccessKeyID string
        SecretKey   string
}

func makeAuthorizationHeader(params *RequestParams) (string, error) {
        if err := hasXAmzDateHeader(params.Headers); err != nil {
                return "", err
        }
        signature, signedHeaders, err := makeSignatureV4(params)
        if err != nil {
                return "", err
        }
        date := params.Headers["X-Amz-Date"][:ISO8601DateEndIndex]
        return fmt.Sprintf("%s Credential=%s/%s/%s/%s/%s, SignedHeaders=%s, Signature=%s",
                Algorithm, params.AccessKeyID, date, params.Region, 
                params.Service, Terminal, signedHeaders, signature), nil
}

func makeSignatureV4(params *RequestParams) (string, string, error) {
        canonicalRequestHash, signedHeaders, err := makeCanonicalRequestHash(params)
        if err != nil {
                return "", "", nil
        }
        stringToSign := makeStringToSign(params, canonicalRequestHash)
        signature := makeSignature(params, stringToSign)
        return signature, signedHeaders, nil
}

func makeCanonicalRequestHash(params *RequestParams) (string, string, error) {
        // Based on https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
        // and https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        
        u, err := url.Parse(params.URL)
        if err != nil {
                return "", "", err
        }

        keys := getKeys(params.Headers)
        sort.Strings(keys)

        var canonicalHeadersArray, signedHeadersArray []string
        for _, k := range keys {
                lowkey := strings.ToLower(k)
                val := params.Headers[k]
                if lowkey != "x-amz-date" {
                        val = strings.ToLower(val)
                }
                canonicalHeader := fmt.Sprintf("%s:%s", lowkey, val)
                signedHeadersArray = append(signedHeadersArray, lowkey)
                canonicalHeadersArray = append(canonicalHeadersArray, canonicalHeader)
        }

        signedHeaders := strings.Join(signedHeadersArray, ";")
        payloadHash := fmt.Sprintf("%x", makeHmac(nil, params.Body))

        canonicalRequest := fmt.Sprintf("%s\n%s\n\n%s\n\n%s\n%s", 
                params.Method,
                u.Path,
                strings.Join(canonicalHeadersArray, "\n"),
                signedHeaders,
                payloadHash)

	hash := makeHmac(nil, []byte(canonicalRequest))
	return fmt.Sprintf("%x", hash), signedHeaders, nil
}

func makeStringToSign(params *RequestParams, canonicalRequestHash string) string {
	var stringToSignRaw string = "%s\n%s\n%s/%s/%s/%s\n%s"
	timestamp := params.Headers["X-Amz-Date"]
        return fmt.Sprintf(stringToSignRaw, Algorithm, timestamp, timestamp[:ISO8601DateEndIndex], params.Region, 
                params.Service, Terminal, canonicalRequestHash)
}

func makeSignature(params *RequestParams, stringToSign string) string {
        date := params.Headers["X-Amz-Date"][:ISO8601DateEndIndex]
        kDate := makeHmac([]byte("AWS4" + params.SecretKey), []byte(date))
        kRegion := makeHmac(kDate, []byte(params.Region))
        kService := makeHmac(kRegion, []byte(params.Service))
        kSigning := makeHmac(kService, []byte(Terminal))
        signature := makeHmac(kSigning, []byte(stringToSign))
        return fmt.Sprintf("%x", signature)
}

func makeHmac(key []byte, data []byte) []byte {
        var h hash.Hash

        if key == nil {
                h = sha256.New()
        } else {
                h = hmac.New(sha256.New, key)
        }
	h.Write(data)
	return h.Sum(nil)
}

func getKeys(m map[string]string) []string {
        var keys []string
        for k, _ := range m {
                keys = append(keys, k)
        }
        return keys
}

func hasXAmzDateHeader(headers map[string]string) error {
        for k, v := range headers {
                if strings.ToLower(k) == "x-amz-date" {
                        if v == "" {
                                return fmt.Errorf("Value of \"X-Amz-Date\" header is empty")
                        }
                        var date, ts int
                        if _, err := fmt.Sscanf(v, "%8dT%6d", &date, &ts); err != nil {
                                return fmt.Errorf("\"X-Amz-Date\" header value is not in ISO8601 format (YYYYMMDDTHHmmssZ)")
                        }
                        return nil
                }
        }
        return fmt.Errorf("\"X-Amz-Date\" header is not set")
}
