package aws

import (
        "fmt"
        "io/ioutil"

        "github.com/aws/aws-sdk-go/aws/session"
        "github.com/aws/aws-sdk-go/service/sts"
        "github.com/aws/aws-sdk-go/aws/request"
)



type IAMAuthElements struct {
        Method  string
        URL     string
        Body    []byte
        Headers map[string][]string
}

func vaultServerHeaderHandler(serverID string) func(*request.Request) {
        return func(req *request.Request) {
                req.HTTPRequest.Header.Set("X-Vault-AWS-IAM-Server-ID", serverID)
        }
}

func GetIAMAuthElements(serverID string) (*IAMAuthElements, error) {
        sess, err := session.NewSession()
        if err != nil {
                return nil, fmt.Errorf("error creating AWS session: %v", err)
        }

        if serverID != "" {
                sess.Handlers.Sign.PushBack(vaultServerHeaderHandler(serverID))
        }
        service := sts.New(sess)
        req, _ := service.GetCallerIdentityRequest(nil)
        if err = req.Sign(); err != nil {
                return nil, fmt.Errorf("error signing AWS request: %v", err)
        }

        body, err := ioutil.ReadAll(req.HTTPRequest.Body)
        if err != nil {
                return nil, fmt.Errorf("error reading request body: %v", err)
        }
        return &IAMAuthElements{
                Method:  req.HTTPRequest.Method,
                URL:     req.HTTPRequest.URL.String(),
                Body:    body,
                Headers: req.HTTPRequest.Header,
        }, nil
}
