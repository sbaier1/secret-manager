package awsutil

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-logr/logr"
	"github.com/hashicorp/errwrap"
	"github.com/pkg/errors"
	"net/http"
	"os"
	"time"
)

type CredentialsConfig struct {
	// The access key if static credentials are being used
	AccessKey string

	// The secret key if static credentials are being used
	SecretKey string

	// The session token if it is being used
	SessionToken string

	// If specified, the region will be provided to the config of the
	// EC2RoleProvider's client. This may be useful if you want to e.g. reuse
	// the client elsewhere.
	Region string

	// The filename for the shared credentials provider, if being used
	Filename string

	// The profile for the shared credentials provider, if being used
	Profile string

	// The http.Client to use, or nil for the client to use its default
	HTTPClient *http.Client

	// The logger to use for credential acquisition debugging
	log logr.Logger
}

func (c *CredentialsConfig) GenerateCredentialChain() (*credentials.Credentials, error) {
	var providers []credentials.Provider

	switch {
	case c.AccessKey != "" && c.SecretKey != "":
		// Add the static credential provider
		providers = append(providers, &credentials.StaticProvider{
			Value: credentials.Value{
				AccessKeyID:     c.AccessKey,
				SecretAccessKey: c.SecretKey,
				SessionToken:    c.SessionToken,
			}})
		c.log.Info("added static credential provider", "AccessKey", c.AccessKey)

	case c.AccessKey == "" && c.SecretKey == "":
		// Attempt to get credentials from the IAM instance role below

	default: // Have one or the other but not both and not neither
		return nil, fmt.Errorf(
			"static AWS client credentials haven't been properly configured (the access key or secret key were provided but not both)")
	}

	roleARN := os.Getenv("AWS_ROLE_ARN")
	tokenPath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	sessionName := os.Getenv("AWS_ROLE_SESSION_NAME")
	if roleARN != "" && tokenPath != "" {
		// this session is only created to create the WebIdentityRoleProvider, as the env variables are already there
		// this automatically assumes the role, but the provider needs to be added to the chain
		c.log.Info("adding web identity provider", "roleARN", roleARN)
		sess, err := session.NewSession()
		if err != nil {
			return nil, errors.Wrap(err, "error creating a new session to create a WebIdentityRoleProvider")
		}
		webIdentityProvider := stscreds.NewWebIdentityRoleProvider(sts.New(sess), roleARN, sessionName, tokenPath)

		// Check if the webIdentityProvider can successfully retrieve
		// credentials (via sts:AssumeRole), and warn if there's a problem.
		if _, err := webIdentityProvider.Retrieve(); err != nil {
			c.log.Error(err, "error assuming role", roleARN, "tokenPath", tokenPath, "sessionName", sessionName, "err", err)
		}

		//Add the web identity role credential provider
		providers = append(providers, webIdentityProvider)
	}

	// Add the environment credential provider
	providers = append(providers, &credentials.EnvProvider{})

	// Add the shared credentials provider
	providers = append(providers, &credentials.SharedCredentialsProvider{
		Filename: c.Filename,
		Profile:  c.Profile,
	})

	// Add the remote provider
	def := defaults.Get()
	if c.Region != "" {
		def.Config.Region = aws.String(c.Region)
	}
	if c.HTTPClient != nil {
		def.Config.HTTPClient = c.HTTPClient
		_, checkFullURI := os.LookupEnv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
		_, checkRelativeURI := os.LookupEnv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
		if !checkFullURI && !checkRelativeURI {
			// match the sdk defaults from https://github.com/aws/aws-sdk-go/pull/3066
			def.Config.HTTPClient.Timeout = 1 * time.Second
			def.Config.MaxRetries = aws.Int(2)
		}
	}

	providers = append(providers, defaults.RemoteCredProvider(*def.Config, def.Handlers))

	// Create the credentials required to access the API.
	creds := credentials.NewChainCredentials(providers)
	if creds == nil {
		return nil, fmt.Errorf("could not compile valid credential providers from static config, environment, shared, web identity or instance metadata")
	}

	return creds, nil
}

// "us-east-1 is used because it's where AWS first provides support for new features,
// is a widely used region, and is the most common one for some services like STS.
const DefaultRegion = "us-east-1"

// This is nil by default, but is exposed in case it needs to be changed for tests.
var ec2Endpoint *string

/*
It's impossible to mimic "normal" AWS behavior here because it's not consistent
or well-defined. For example, boto3, the Python SDK (which the aws cli uses),
loads `~/.aws/config` by default and only reads the `AWS_DEFAULT_REGION` environment
variable (and not `AWS_REGION`, while the golang SDK does _mostly_ the opposite -- it
reads the region **only** from `AWS_REGION` and not at all `~/.aws/config`, **unless**
the `AWS_SDK_LOAD_CONFIG` environment variable is set. So, we must define our own
approach to walking AWS config and deciding what to use.
Our chosen approach is:
	"More specific takes precedence over less specific."
1. User-provided configuration is the most explicit.
2. Environment variables are potentially shared across many invocations and so they have less precedence.
3. Configuration in `~/.aws/config` is shared across all invocations of a given user and so this has even less precedence.
4. Configuration retrieved from the EC2 instance metadata service is shared by all invocations on a given machine, and so it has the lowest precedence.
This approach should be used in future updates to this logic.
*/
func GetRegion(configuredRegion string) (string, error) {
	if configuredRegion != "" {
		return configuredRegion, nil
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return "", errwrap.Wrapf("got error when starting session: {{err}}", err)
	}

	region := aws.StringValue(sess.Config.Region)
	if region != "" {
		return region, nil
	}

	metadata := ec2metadata.New(sess, &aws.Config{
		Endpoint:                          ec2Endpoint,
		EC2MetadataDisableTimeoutOverride: aws.Bool(true),
		HTTPClient: &http.Client{
			Timeout: time.Second,
		},
	})
	if !metadata.Available() {
		return DefaultRegion, nil
	}

	region, err = metadata.Region()
	if err != nil {
		return "", errwrap.Wrapf("unable to retrieve region from instance metadata: {{err}}", err)
	}

	return region, nil
}

// STS is a really weird service that used to only have global endpoints but now has regional endpoints as well.
// For backwards compatibility, even if you request a region other than us-east-1, it'll still sign for us-east-1.
// See, e.g., https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html#id_credentials_temp_enable-regions_writing_code
// So we have to shim in this EndpointResolver to force it to sign for the right region
func StsSigningResolver(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
	defaultEndpoint, err := endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
	if err != nil {
		return defaultEndpoint, err
	}
	defaultEndpoint.SigningRegion = region
	return defaultEndpoint, nil
}

// Retrieve AWS credentials from static > environment > shared > instance metadata, in that order of priority.
func RetrieveCreds(accessKey, secretKey, sessionToken string, logger logr.Logger) (*credentials.Credentials, error) {
	credConfig := &CredentialsConfig{
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		SessionToken: sessionToken,
		log:          logger,
	}
	creds, err := credConfig.GenerateCredentialChain()
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, fmt.Errorf("could not compile valid credential providers from static config, environment, shared, or instance metadata")
	}

	_, err = creds.Get()
	if err != nil {
		return nil, errwrap.Wrapf("failed to retrieve credentials from credential chain: {{err}}", err)
	}
	return creds, nil
}
