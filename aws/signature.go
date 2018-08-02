package aws

import (
        "fmt"
        "hash"
        "crypto/hmac"
	"crypto/sha256"
	"strings"
	"time"

	// "github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	Region string = "us-east-1"

	Service string = "sts"

        Terminal string = "aws4_request"
        
        RequestBody string = "Action=GetCallerIdentity&Version=2011-06-15"
)

func MakeSignature(secret string) string {
	var (
		now                  = nowAsISO8601()
		canonicalRequestHash = makeCanonicalRequestHash(now)
                stringToSign         = makeStringToSign(now, canonicalRequestHash)
                signature            = makeSignature(secret, stringToSign, now)
        )
        return signature
}

func nowAsISO8601() string {
	return strings.Replace(strings.Replace(time.Now().UTC().Format(time.RFC3339), "-", "", -1), ":", "", -1)
}

func makeCanonicalRequestHash(ts string) string {
	// Based on https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
	// and https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
	var canonicalRequestRaw string = `POST
/

accept-encoding:identity
content-length:32
content-type:application/x-www-form-urlencoded
host:sts.amazonaws.com
x-amz-date:%s
accept-encoding;content-length;content-type;host;x-amz-date
%s`

        payloadHash := fmt.Sprintf("%x", makeHmac(nil, []byte(RequestBody)))
        canonicalRequest := fmt.Sprintf(canonicalRequestRaw, ts, payloadHash)
	hash := makeHmac(nil, []byte(canonicalRequest))
	return fmt.Sprintf("%x", hash)
}

func makeStringToSign(ts, canonicalRequestHash string) string {
	var stringToSignRaw string = "AWS4-HMAC-sha256\n%s\n%s/%s/%s/%s\n%s"
	date := ts[:8]
	return fmt.Sprintf(stringToSignRaw, ts, date, Region, Service, Terminal, canonicalRequestHash)
}

func makeSignature(ts, stringToSign, secret string) string {
        date := ts[:8]
        hash := makeHmac(makeHmac(makeHmac(makeHmac(makeHmac([]byte("AWS4" + secret), []byte(date)), []byte(Region)), []byte(Service)), []byte(Terminal)), []byte(stringToSign))
        return fmt.Sprintf("%x", hash)
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
