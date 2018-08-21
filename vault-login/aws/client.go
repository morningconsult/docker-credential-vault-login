package aws

import (
        "io/ioutil"

        log "github.com/cihub/seelog"
        "github.com/aws/aws-sdk-go/aws/session"
        "github.com/aws/aws-sdk-go/service/sts"
        "github.com/aws/aws-sdk-go/aws/request"
)

const DefaultSTSGetCallerIdentityBody string = "Action=GetCallerIdentity&Version=2011-06-15"

type IAMAuthElements struct {
        Method  string
        URL     string
        Body    []byte
        Headers map[string][]string
}

type Client interface {
        GetIAMAuthElements(string) (*IAMAuthElements, error)
}

type defaultClient struct {
        awsSession *session.Session
}

func NewDefaultClient() (*defaultClient, error) {
        sess, err := session.NewSession()
        if err != nil {
                return nil, err
        }

        return &defaultClient{
                awsSession: sess,
        }, nil
}

// GetIAMAuthElements creates an sts:GetCallerIdentity request
// and returns the components of the request required by Vault
// to authenticate against AWS IAM, including the request method,
// URL, body, and headers.
func (d *defaultClient) GetIAMAuthElements(serverID string) (*IAMAuthElements, error) {
        if serverID != "" {
                d.awsSession.Handlers.Sign.PushBack(vaultServerHeaderHandler(serverID))
        }

        service := sts.New(d.awsSession)
        req, _ := service.GetCallerIdentityRequest(nil)
        if err := req.Sign(); err != nil {
                return nil, err
        }

        body, err := ioutil.ReadAll(req.HTTPRequest.Body)
        if err != nil {
                log.Debugf("Error reading sts:GetCallerIdentity request body. Using default value %q instead. Error message:\n%v", 
                        DefaultSTSGetCallerIdentityBody)
        } else {
                body = []byte(DefaultSTSGetCallerIdentityBody)
        }

        return &IAMAuthElements{
                Method:  req.HTTPRequest.Method,
                URL:     req.HTTPRequest.URL.String(),
                Body:    body,
                Headers: req.HTTPRequest.Header,
        }, nil
}

func vaultServerHeaderHandler(serverID string) func(*request.Request) {
        return func(req *request.Request) {
                req.HTTPRequest.Header.Set("X-Vault-AWS-IAM-Server-ID", serverID)
        }
}
