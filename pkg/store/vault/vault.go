/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/go-logr/logr"

	vault "github.com/hashicorp/vault/api"

	smmeta "github.com/itscontained/secret-manager/pkg/apis/meta/v1"
	smv1alpha1 "github.com/itscontained/secret-manager/pkg/apis/secretmanager/v1alpha1"
	ctxlog "github.com/itscontained/secret-manager/pkg/log"
	"github.com/itscontained/secret-manager/pkg/store"
	"github.com/itscontained/secret-manager/pkg/store/schema"
	"github.com/itscontained/secret-manager/pkg/util/awsutil"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/types"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var _ store.Client = &Vault{}

type Client interface {
	NewRequest(method, requestPath string) *vault.Request
	RawRequestWithContext(ctx context.Context, r *vault.Request) (*vault.Response, error)
	SetToken(v string)
	Token() string
}

type Vault struct {
	kube      ctrlclient.Client
	store     smv1alpha1.GenericStore
	namespace string
	log       logr.Logger
	client    Client
}

func init() {
	schema.Register(&Vault{}, &smv1alpha1.SecretStoreSpec{
		Vault: &smv1alpha1.VaultStore{},
	})
}

func (v *Vault) New(ctx context.Context, store smv1alpha1.GenericStore, kube ctrlclient.Client, namespace string) (store.Client, error) {
	log := ctxlog.FromContext(ctx)
	vClient := &Vault{
		kube:      kube,
		namespace: namespace,
		store:     store,
		log:       log,
	}

	cfg, err := vClient.newConfig()
	if err != nil {
		return nil, err
	}

	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("error initializing Vault client: %s", err.Error())
	}

	if vClient.store.GetSpec().Vault.Namespace != nil {
		client.SetNamespace(*vClient.store.GetSpec().Vault.Namespace)
	}

	if err := vClient.setToken(ctx, client); err != nil {
		return nil, err
	}

	vClient.client = client

	return vClient, nil
}

func (v *Vault) GetSecret(ctx context.Context, ref smv1alpha1.RemoteReference) ([]byte, error) {
	version := ""
	if ref.Version != nil {
		version = *ref.Version
	}

	data, err := v.readSecret(ctx, ref.Name, ref.IgnoreStructure, version)
	if err != nil {
		return nil, err
	}
	property := ""
	if ref.Property != nil {
		property = *ref.Property
	}
	value, exists := data[property]
	if !exists {
		return nil, fmt.Errorf("property %q not found in secret response", property)
	}
	return value, nil
}

func (v *Vault) GetSecretMap(ctx context.Context, ref smv1alpha1.RemoteReference) (map[string][]byte, error) {
	version := ""
	if ref.Version != nil {
		version = *ref.Version
	}

	return v.readSecret(ctx, ref.Name, ref.IgnoreStructure, version)
}

func (v *Vault) readSecret(ctx context.Context, path string, ignoreStructure bool, version string) (map[string][]byte, error) {
	storeSpec := v.store.GetSpec()
	kvPath := storeSpec.Vault.Path

	kvVersion := smv1alpha1.DefaultVaultKVEngineVersion
	if storeSpec.Vault.Version != nil {
		kvVersion = *storeSpec.Vault.Version
	}

	if kvVersion == smv1alpha1.DefaultVaultKVEngineVersion {
		if !strings.HasSuffix(kvPath, "/data") {
			kvPath = fmt.Sprintf("%s/data", kvPath)
		}
	}

	req := v.client.NewRequest(http.MethodGet, fmt.Sprintf("/v1/%s/%s", kvPath, path))
	if version != "" {
		req.Params.Set("version", version)
	}

	resp, err := v.client.RawRequestWithContext(ctx, req)
	if err != nil {
		return nil, err
	}

	vaultSecret, err := vault.ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}

	secretData := vaultSecret.Data
	if kvVersion == smv1alpha1.DefaultVaultKVEngineVersion {
		dataInt, ok := vaultSecret.Data["data"]
		if !ok {
			return nil, fmt.Errorf("unexpected secret data response")
		}
		secretData, ok = dataInt.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected secret data format")
		}
	}

	byteMap := make(map[string][]byte, len(secretData))
	for k, v := range secretData {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected secret type")
		}
		if ignoreStructure {
			decodedValue, err := base64.StdEncoding.DecodeString(str)
			if err != nil {
				return nil, fmt.Errorf("secret data at key %q was not encoded as base64", k)
			}
			byteMap[k] = decodedValue
		} else {
			byteMap[k] = []byte(str)
		}
	}

	return byteMap, nil
}

func (v *Vault) newConfig() (*vault.Config, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = v.store.GetSpec().Vault.Server

	certs := v.store.GetSpec().Vault.CABundle
	if len(certs) == 0 {
		return cfg, nil
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(certs)
	if !ok {
		return nil, fmt.Errorf("error loading Vault CA bundle")
	}

	cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = caCertPool

	return cfg, nil
}

func (v *Vault) setToken(ctx context.Context, client Client) error {
	tokenRef := v.store.GetSpec().Vault.Auth.TokenSecretRef
	if tokenRef != nil {
		token, err := v.secretKeyRefOrEmptyString(ctx, tokenRef)
		if err != nil {
			return err
		}
		client.SetToken(token)

		return nil
	}

	appRole := v.store.GetSpec().Vault.Auth.AppRole
	if appRole != nil {
		token, err := v.requestTokenWithAppRoleRef(ctx, client, appRole)
		if err != nil {
			return err
		}
		client.SetToken(token)

		return nil
	}

	awsAuth := v.store.GetSpec().Vault.Auth.AWS
	if awsAuth != nil {
		token, err := v.requestTokenWithAWSAuth(ctx, awsAuth, client)
		if err != nil {
			return err
		}
		client.SetToken(token)

		return nil
	}

	kubernetesAuth := v.store.GetSpec().Vault.Auth.Kubernetes
	if kubernetesAuth != nil {
		token, err := v.requestTokenWithKubernetesAuth(ctx, client, kubernetesAuth)
		if err != nil {
			return fmt.Errorf("error reading Kubernetes service account token. error: %s", err.Error())
		}
		client.SetToken(token)
		return nil
	}

	return fmt.Errorf("error initializing Vault client: tokenSecretRef, appRoleSecretRef, or Kubernetes auth role not set")
}

func (v *Vault) secretKeyRefOrEmptyString(ctx context.Context, selector *smmeta.SecretKeySelector) (string, error) {
	if selector.Name != "" && selector.Key != "" {
		ref, err := v.secretKeyRef(ctx, v.namespace, selector.Name, selector.Key)
		if err != nil {
			return "", err
		}
		return ref, nil
	}
	return "", nil
}

func (v *Vault) secretKeyRef(ctx context.Context, namespace, name, key string) (string, error) {
	secret := &corev1.Secret{}
	ref := types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}
	err := v.kube.Get(ctx, ref, secret)
	if err != nil {
		return "", err
	}

	keyBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("no data for %q in secret '%s/%s'", key, namespace, name)
	}

	value := string(keyBytes)
	valueStr := strings.TrimSpace(value)

	return valueStr, nil
}

func (v *Vault) requestTokenWithAppRoleRef(ctx context.Context, client Client, appRole *smv1alpha1.VaultAppRole) (string, error) {
	roleID := strings.TrimSpace(appRole.RoleID)

	secretID, err := v.secretKeyRefOrEmptyString(ctx, &appRole.SecretRef)
	if err != nil {
		return "", err
	}

	parameters := map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	authPath := appRole.Path
	if authPath == "" {
		authPath = smv1alpha1.DefaultVaultAppRoleAuthMountPath
	}

	url := strings.Join([]string{"/v1", "auth", authPath, "login"}, "/")
	request := client.NewRequest("POST", url)

	err = request.SetJSONBody(parameters)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	resp, err := client.RawRequestWithContext(ctx, request)
	if err != nil {
		return "", fmt.Errorf("error logging in to Vault server: %s", err.Error())
	}

	defer resp.Body.Close()

	vaultResult := vault.Secret{}
	if err = resp.DecodeJSON(&vaultResult); err != nil {
		return "", fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	token, err := vaultResult.TokenID()
	if err != nil {
		return "", fmt.Errorf("unable to read token: %s", err.Error())
	}

	if token == "" {
		return "", errors.New("no token returned")
	}

	return token, nil
}

func (v *Vault) requestTokenWithKubernetesAuth(ctx context.Context, client Client, kubernetesAuth *smv1alpha1.VaultKubernetesAuth) (string, error) {
	var jwt string
	var err error
	if kubernetesAuth.SecretRef == nil {
		tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
		if _, err = os.Stat(tokenPath); !os.IsNotExist(err) {
			var jwtByte []byte
			jwtByte, err = ioutil.ReadFile(tokenPath)
			if err != nil {
				return "", fmt.Errorf("could not get serviceaccount jwt from disk. error: %s", err)
			}
			jwt = string(jwtByte)
		}
	} else {
		tokenRef := kubernetesAuth.SecretRef
		if tokenRef.Key == "" {
			tokenRef = kubernetesAuth.SecretRef.DeepCopy()
			tokenRef.Key = "token"
		}
		jwt, err = v.secretKeyRefOrEmptyString(ctx, tokenRef)
		if err != nil {
			return "", err
		}
	}

	parameters := map[string]string{
		"role": kubernetesAuth.Role,
		"jwt":  jwt,
	}
	authPath := kubernetesAuth.Path
	if authPath == "" {
		authPath = smv1alpha1.DefaultVaultKubernetesAuthMountPath
	}
	url := strings.Join([]string{"/v1", "auth", authPath, "login"}, "/")
	request := client.NewRequest("POST", url)

	err = request.SetJSONBody(parameters)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	resp, err := client.RawRequestWithContext(ctx, request)
	if err != nil {
		return "", fmt.Errorf("error calling Vault server: %s", err.Error())
	}

	defer resp.Body.Close()
	vaultResult := vault.Secret{}
	err = resp.DecodeJSON(&vaultResult)
	if err != nil {
		return "", fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	token, err := vaultResult.TokenID()
	if err != nil {
		return "", fmt.Errorf("unable to read token: %s", err.Error())
	}

	return token, nil
}

func (v *Vault) requestTokenWithAWSAuth(ctx context.Context, auth *smv1alpha1.VaultAWSAuth, client Client) (string, error) {
	var err error
	mount := auth.Path

	var id *smmeta.SecretKeySelector
	var key *smmeta.SecretKeySelector
	aKid := ""
	sKey := ""
	if auth.AWS != nil {
		id = auth.AWS.AccessKeyID
		key = auth.AWS.SecretAccessKey
		aKid, err = v.secretKeyRefOrEmptyString(ctx, id)
		if err != nil {
			return "", fmt.Errorf("error generating AWS login credentials: %s", err.Error())
		}
		sKey, err = v.secretKeyRefOrEmptyString(ctx, key)
		if err != nil {
			return "", fmt.Errorf("error generating AWS login credentials: %s", err.Error())
		}
	}
	creds, err := awsutil.RetrieveCreds(
		aKid,
		sKey,
		// TODO this is not supported in the CRD yet
		"",
		v.log)
	if err != nil {
		return "", fmt.Errorf("error generating AWS login credentials: %s", err.Error())
	}

	headerValue := auth.IamServerIDHeaderValue
	region := auth.Region
	if region == "" {
		region = awsutil.DefaultRegion
	}
	loginData, err := v.GenerateAWSLoginData(creds, headerValue, region)
	if err != nil {
		return "", err
	}
	if loginData == nil {
		return "", fmt.Errorf("got nil response from GenerateAWSLoginData")
	}
	loginData["role"] = auth.Role

	if mount == "" {
		mount = smv1alpha1.DefaultVaultKubernetesAuthMountPath
	}
	url := strings.Join([]string{"/v1", "auth", mount, "login"}, "/")
	request := client.NewRequest("POST", url)

	err = request.SetJSONBody(loginData)
	if err != nil {
		return "", fmt.Errorf("error encoding Vault parameters: %s", err.Error())
	}

	resp, err := client.RawRequestWithContext(ctx, request)
	if err != nil {
		return "", fmt.Errorf("error calling Vault server: %s", err.Error())
	}

	defer resp.Body.Close()
	vaultResult := vault.Secret{}
	err = resp.DecodeJSON(&vaultResult)
	if err != nil {
		return "", fmt.Errorf("unable to decode JSON payload: %s", err.Error())
	}

	token, err := vaultResult.TokenID()
	if err != nil {
		return "", fmt.Errorf("unable to read token: %s", err.Error())
	}

	return token, nil
}

// GenerateAWSLoginData populates the necessary data to send to the Vault server for generating a token
// This is useful for other API clients to use
func (v *Vault) GenerateAWSLoginData(creds *credentials.Credentials, headerValue, configuredRegion string) (map[string]interface{}, error) {
	loginData := make(map[string]interface{})

	// Use the credentials we've found to construct an STS session
	region, err := awsutil.GetRegion(configuredRegion)
	if err != nil {
		v.log.Info(fmt.Sprintf("defaulting region to %q due to %s", awsutil.DefaultRegion, err.Error()))
		region = awsutil.DefaultRegion
	}
	stsSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials:      creds,
			Region:           &region,
			EndpointResolver: endpoints.ResolverFunc(awsutil.StsSigningResolver),
		},
	})
	if err != nil {
		return nil, err
	}

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	// Inject the required auth header value, if supplied, and then sign the request including that header
	if headerValue != "" {
		stsRequest.HTTPRequest.Header.Add("X-Vault-AWS-IAM-Server-ID", headerValue)
	}
	err = stsRequest.Sign()
	if err != nil {
		return nil, err
	}

	// Now extract out the relevant parts of the request
	headersJSON, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}
	loginData["iam_http_request_method"] = stsRequest.HTTPRequest.Method
	loginData["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	loginData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headersJSON)
	loginData["iam_request_body"] = base64.StdEncoding.EncodeToString(requestBody)

	return loginData, nil
}
