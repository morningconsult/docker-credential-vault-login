package aws

import (
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

// TestReadsEnvFirst tests that the GetIAMAuthElements function
// first reads credentials from the AWS environment variables
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

func TestMain(m *testing.M) {
        saveEnvVars()
        status := m.Run()
        restoreEnvVars()
        os.Exit(status)
}
func extractAccessKeyIDFromHeaders(t *testing.T, headers map[string][]string) string {
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
