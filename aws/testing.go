package aws

import (
        "fmt"
        "strings"
        "testing"
)

const (
        AuthHMACMethod string = "AWS4-HMAC-SHA256"

        AuthSignedHeaders string = "content-length;content-type;host;x-amz-date;x-vault-aws-iam-server-id"

        AuthRegion string = "us-east-1"

        AuthService string = "sts"

        AuthTerminal string = "aws4_request"
)

func validateAuthorization(t *testing.T, authorization, testAccessKey string) {
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
