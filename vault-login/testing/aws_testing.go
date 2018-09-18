package test

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	EnvAWSAccessKey string = "AWS_ACCESS_KEY"

	EnvAWSSecretKey string = "AWS_SECRET_KEY"

	TestAccessKey string = "AKIAIJWPJLKME2OBDB6Q"

	TestSecretKey string = "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"
	
	AuthHMACMethod string = "AWS4-HMAC-SHA256"

	AuthSignedHeaders string = "content-length;content-type;host;x-amz-date;x-vault-aws-iam-server-id"

	AuthRegion string = "us-east-1"

	AuthService string = "sts"

	AuthTerminal string = "aws4_request"
)

func SetTestAWSEnvVars() {
	os.Setenv(EnvAWSAccessKey, TestAccessKey)
	os.Setenv(EnvAWSSecretKey, TestSecretKey)
}

func ValidateAuthorization(t *testing.T, authorization, testAccessKey string) {
	auths := strings.Split(authorization, " ")
	if len(auths) != 4 {
		t.Errorf("%s %s %s", "\"Authorization\" header of sts:GetCallerIdentity request",
			"should have exactly 4 elements (see",
			"https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html)")
	}
	if auths[0] != AuthHMACMethod {
		t.Errorf("Algorithm in \"Authorization\" header of sts:GetCallerIdentity request (Got: %q, Expected %q)",
			auths[0], AuthHMACMethod)
	}
	validateCredential(t, auths[1], testAccessKey)
	validateSignedHeaders(t, auths[2])
	validateSignature(t, auths[3])
}

func validateCredential(t *testing.T, credential, testAccessKey string) {
	credential = strings.TrimLeft(credential, "Credential=")
	elems := strings.Split(credential, "/")
	if len(elems) != 5 {
		t.Errorf("%s %s %s", "The \"Credential\" element of the \"Authorization\" header",
			"of sts:GetCallerIdentity request should have exactly 4 elements (see",
			"https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html)")
	}
	if elems[0] != testAccessKey {
		t.Errorf("%s %s (Got: %q, Expected: %q)", "unexpected access key in \"Credential\" element",
			"of \"Authorization\" header of sts:GetCallerIdentity request", elems[0], testAccessKey)
	}
	var date int
	if _, err := fmt.Sscanf(elems[1], "%8d", &date); err != nil {
		t.Errorf("%s %s (Got: %q, Expected: YYYYMMDD)", "malformed date in \"Credential\" element",
			"of \"Authorization\" header of sts:GetCallerIdentity request", elems[0])
	}
	if elems[2] != AuthRegion {
		t.Errorf("%s %s (Got: %q, Expected: %q)", "unexpected region in \"Credential\" element",
			"of \"Authorization\" header of sts:GetCallerIdentity request", elems[2], AuthRegion)
	}
	if elems[3] != AuthService {
		t.Errorf("%s %s (Got: %q, Expected: %q)", "unexpected service in \"Credential\" element",
			"of \"Authorization\" header of sts:GetCallerIdentity request", elems[3], AuthService)
	}
	terminal := strings.Trim(elems[4], ",")
	if terminal != AuthTerminal {
		t.Errorf("%s %s (Got: %q, Expected: %q)", "unexpected terminal value in \"Credential\" element",
			"of \"Authorization\" header of sts:GetCallerIdentity request", terminal, AuthTerminal)
	}
}

func validateSignedHeaders(t *testing.T, signedHeaders string) {
	expected := fmt.Sprintf("SignedHeaders=%s,", AuthSignedHeaders)
	if signedHeaders != expected {
		t.Errorf("%s %s (Got: %q, Expected: %q)", "unexpected \"SignedHeaders\" element",
			"of \"Authorization\" header of sts:GetCallerIdentity request",
			signedHeaders, expected)
	}
}

func validateSignature(t *testing.T, signature string) {
	var buf []byte
	if _, err := fmt.Sscanf(signature, "Signature=%64x", &buf); err != nil {
		t.Errorf("%s %s (see %s)", "malformed \"Signature\" element",
			"of \"Authorization\" header of sts:GetCallerIdentity request",
			"https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html")
	}
}

func ExtractAccessKeyIDFromHeaders(t *testing.T, headers map[string][]string) string {
	var (
		cred = ""
		auth []string
		ok   bool
	)

	if auth, ok = headers["Authorization"]; !ok {
		t.Fatal("sts:GetCallerIdentity request headers does not contain \"Authorization\" header")
	}

	vals := strings.Split(auth[0], " ")
	for _, v := range vals {
		if i := strings.Index(v, "Credential="); i != -1 {
			cred = v
			break
		}
	}
	if cred == "" {
		t.Fatalf("\"Authorization\" header of the sts:GetCallerIdentity request does not have a Credential value")
	}

	start := strings.Index(cred, "=")
	if start == -1 {
		t.Fatalf("Malformed \"Authorization\" header in sts:GetCallerIdentity request")
	}
	cred = cred[start + 1:]
	return strings.Split(cred, "/")[0]
}
