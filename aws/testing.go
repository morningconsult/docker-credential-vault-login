package aws

// import (
//         "strings"
//         "testing"
// )

// const (
//         AuthHMACMethod string = "AWS4-HMAC-SHA256"

//         AuthSignedHeaders string = "content-length;content-type;host;x-amz-date;x-vault-aws-iam-server-id"

//         AuthRegion string = "us-east-1"

//         AuthService string = "sts"

//         AuthTerminal string = "aws4_request"
// )

// func verifyAuthorization(t *testing.T, authorization string) {
//         auths := strings.Split(authorization)
//         if auths[0] != AuthHMACMethod {
//                 t.Errorf("\"Authorization\" header of sts:GetCallerIdentity request  (Got: %q, Expected %q)", )
//         }
// }