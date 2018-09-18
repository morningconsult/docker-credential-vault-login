package aws

import (
	"fmt"
	"io/ioutil"

	log "github.com/cihub/seelog"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/aws/request"
	ec2 "github.com/aws/aws-sdk-go/aws/ec2metadata"
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
	GetPKCS7Signature() (string, error)
}

type defaultClient struct {
	awsSession *session.Session
}

func NewDefaultClient() (*defaultClient, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("error creating new AWS client: %v", err)
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
		return nil, fmt.Errorf("error signing sts:GetCallerIdentityRequest: %v", err)
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

// GetPKCS7Signature gets the EC2 instance's PKCS7 signature
// from the instance metadata.
func (d *defaultClient) GetPKCS7Signature() (string, error) {
	service := ec2.New(d.awsSession)
	pkcs7, err := service.GetDynamicData("instance-identity/pkcs7")
	if err != nil {
		return "", fmt.Errorf("error getting PKCS7 signature: %v", err)
	}

	return pkcs7, nil
}

func vaultServerHeaderHandler(serverID string) func(*request.Request) {
	return func(req *request.Request) {
		req.HTTPRequest.Header.Set("X-Vault-AWS-IAM-Server-ID", serverID)
	}
}
