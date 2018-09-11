package vault

// import (
//         "testing"

//         "github.com/aws/aws-sdk-go/awstesting"

//         test "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/testing"
// )

// oldEnv := awstesting.StashEnv()
// defer awstesting.PopEnv(oldEnv)
// test.SetTestAWSEnvVars()

// server := makeMockVaultServer()
// go server.Listenandserve()

// client := test.NewPreConfiguredVaultClient(t, cluster)
// THE TEST:
// c.getAndSetToken(client, MOCK)