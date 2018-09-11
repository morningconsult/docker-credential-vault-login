package vault

// import (
//         "testing"

//         "github.com/aws/aws-sdk-go/awstesting"
//         gomock "github.com/golang/mock/gomock"
//         test "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/testing"
//         mock_aws "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/aws/mocks"
// )

// 
// cluster := test.StartTestCluster(t)
// defer cluster.Cleanup()
// client := test.NewPreConfiguredVaultClient(t, cluster)
// THE TEST:
// c.getAndSetToken(client, MOCK)
// func TestTest(t *testing.T) {
//         ctrl := gomock.NewController(t)
//         defer ctrl.Finish()

//         awsClient := mock_aws.NewMockClient(ctrl)
//         awsClient.EXPECT().GetIAMAuthElements(gomock.Any()).Return()
// }