package aws

import (
        "fmt"
        "os"
        "strings"
	"testing"
)

const (
        EnvAWSAccessKeyID string = "AWS_ACCESS_KEY_ID"

        EnvAWSAccessKey string = "AWS_ACCESS_KEY"

        EnvAWSSecretAccessKey string = "AWS_SECRET_ACCESS_KEY"

        EnvAWSSecretKey string = "AWS_SECRET_KEY"

        TestAccessKey string = "AKIAIJWPJLKME2OBDB6Q"

        TestSecretKey string = "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"
)

var savedEnvVars map[string]string

// TestReadsEnvFirst tests that GetIAMAuthElements first
// reads credentials from the AWS environment variables
// if they are set.
func TestReadsEnvFirst(t *testing.T) {
        setTestEnvVars()
        elems, err := GetIAMAuthElements("")
        if err != nil {
                t.Fatalf("error creating sts:GetCallerIdentity request: %v", err)
        }
        accessKey := extractAccessKeyIDFromHeaders(t, elems.Headers)
        
        if accessKey != TestAccessKey {
                t.Errorf("%s %s\nGot:\n%q\n\nExpected:\n%q\n", "Credential value of the \"Authorization\" header", 
                        "of the sts:GetCallerIdentity request has the wrong AWS Access Key ID:\n",
                        accessKey, TestAccessKey)
        }
}

// TestWithoutServerID tests that GetIAMAuthElements creates a
// request object without an X-Vault-AWS-IAM-Server-ID header
// when serverID is an empty string
func TestWithoutServerID(t *testing.T) {
        var serverID = ""

        setTestEnvVars()
        elems, err := GetIAMAuthElements(serverID)
        if err != nil {
                t.Fatalf("error creating sts:GetCallerIdentity request: %v", err)
        }

        for k, _ := range elems.Headers {
                if strings.ToLower(k) == "x-vault-aws-iam-server-id" {
                        t.Errorf("%s %s", "GetIAMAuthElements should not add a",
                                "\"X-Vault-AWS-IAM-Server-ID\" header when serverID is an empty string")
                }
        }
}

// TestWithServerID tests that GetIAMAuthElements creates a
// request object with an X-Vault-AWS-IAM-Server-ID header when
// serverID is not an empty string
func TestWithServerID(t *testing.T) {
        var serverID = "vault.example.com"

        setTestEnvVars()
        elems, err := GetIAMAuthElements(serverID)
        if err != nil {
                t.Fatalf("error creating sts:GetCallerIdentity request: %v", err)
        }

        var present = false
        for k, _ := range elems.Headers {
                if strings.ToLower(k) == "x-vault-aws-iam-server-id" {
                        present = true
                        break
                }
        }
        if !present {
                t.Errorf("%s %s", "GetIAMAuthElements should add a",
                                "\"X-Vault-AWS-IAM-Server-ID\" header when serverID is not empty")
        }
}

// TestExpectedValues tests that GetIAMAuthElements creates an
// IAMAuthElements struct with expected values when provided AWS
// credentials (via environment variables in this unit test) 
// and a server ID.
func TestExpectedValues(t *testing.T) {
        var (
                serverID = "vault.example.com"
                expected = IAMAuthElements{
                        Method:  "POST",
                        URL:     "https://sts.amazonaws.com/",
                        Body:    []byte("Action=GetCallerIdentity&Version=2011-06-15"),
                        Headers: map[string][]string{
                                "Content-Type":              []string{
                                        "application/x-www-form-urlencoded; charset=utf-8",
                                },
                                "Content-Length":            []string{"43"},
                                "X-Vault-Aws-Iam-Server-Id": []string{serverID},
                                "X-Amz-Date":                []string{},
                                "Authorization":             []string{},
                                "User-Agent":                []string{},
                        },
                }
        )

        setTestEnvVars()
        elems, err := GetIAMAuthElements(serverID)
        if err != nil {
                t.Fatalf("error creating sts:GetCallerIdentity request: %v", err)
        }

        if elems.Method != expected.Method {
                t.Errorf("got unexpected HTTP request method (Got: %q; Expected: %q)", 
                        elems.Method, expected.Method)
        }
        if elems.URL != expected.URL {
                t.Errorf("got unexpected HTTP request URL (Got: %q; Expected: %q)", 
                        elems.URL, expected.URL)
        }
        if string(elems.Body) != string(expected.Body) {
                t.Errorf("got unexpected HTTP request body (Got: %q; Expected %q)",
                        string(elems.Body), string(expected.Body))
        }

        for k, v := range expected.Headers {
                if d, ok := elems.Headers[k]; !ok && len(d) > 0 {
                        t.Errorf("request headers returned by GetIAMAuthElements do not contain header %q", k)
                }

                switch k {
                case "X-Amz-Date":
                        var date, time int
                        if _, err = fmt.Sscanf(elems.Headers[k][0], "%8dT%6dZ", &date, &time); err != nil {
                                t.Errorf("value of \"X-Amz-Date\" header returned by GetIAMAuthElements is malformed")
                        }
                case "Authorization":
                        validateAuthorization(t, elems.Headers[k][0], TestAccessKey)
                case "User-Agent":
                        continue
                default:
                        if v[0] != elems.Headers[k][0] {
                                t.Errorf("unexpected value of header %q returned by GetIAMAuthElements (Got: %q, Expected %q)",
                                        k, elems.Headers[k], v)
                        }
                }
        }
}

func TestMain(m *testing.M) {
        saveEnvVars()
        status := m.Run()
        restoreEnvVars()
        os.Exit(status)
}

func clearEnvVars() {
        os.Unsetenv(EnvAWSAccessKeyID)
        os.Unsetenv(EnvAWSAccessKey)
        os.Unsetenv(EnvAWSSecretAccessKey)
        os.Unsetenv(EnvAWSSecretKey)
}

func saveEnvVars() {
        clearEnvVars()
        savedEnvVars = map[string]string{
                EnvAWSAccessKey:       os.Getenv(EnvAWSAccessKey),
                EnvAWSAccessKeyID:     os.Getenv(EnvAWSAccessKeyID),
                EnvAWSSecretAccessKey: os.Getenv(EnvAWSSecretAccessKey),
                EnvAWSSecretKey:       os.Getenv(EnvAWSSecretKey),
        }
}

func setTestEnvVars() {
        os.Setenv(EnvAWSAccessKey, TestAccessKey)
        os.Setenv(EnvAWSSecretKey, TestSecretKey)
}

func restoreEnvVars() {
        for k, v := range savedEnvVars {
                os.Setenv(k, v)
        }
}
