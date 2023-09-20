/*
    _____           _____   _____   ____          ______  _____  ------
   |     |  |      |     | |     | |     |     | |       |            |
   |     |  |      |     | |     | |     |     | |       |            |
   | --- |  |      |     | |-----| |---- |     | |-----| |-----  ------
   |     |  |      |     | |     | |     |     |       | |       |
   | ____|  |_____ | ____| | ____| |     |_____|  _____| |_____  |_____


   Licensed under the MIT License <http://opensource.org/licenses/MIT>.

   Copyright © 2020-2023 Microsoft Corporation. All rights reserved.
   Author : <blobfusedev@microsoft.com>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE
*/

package azstorage

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/Azure/azure-storage-fuse/v2/common/log"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/pkg/errors"

	"github.com/Azure/azure-storage-azcopy/v10/azbfs"
	"github.com/Azure/azure-storage-blob-go/azblob"
)

// Verify that the Auth implement the correct AzAuth interfaces
var _ azAuth = &azAuthBlobIMDS{}
var _ azAuth = &azAuthBfsIMDS{}

type azAuthIMDS struct {
	azAuthBase
}

type TokenResponse struct {
	AccessToken string    `json:"token"`
	ExpiresOn   time.Time `json:"expiresOn"`
}

func (azimds *azAuthIMDS) getTokenFromIdentitySidecar(ResourceId string, ResourceArmId string) (r TokenResponse, err error) {
	headers := map[string]string{
		"resource_arm_id": ResourceArmId,
	}

	queryParams := url.Values{
		"resource":   []string{ResourceId},
		"apiVersion": []string{"2018-02-01"},
	}

	httpResponse, err := httpGetRequestWithCustomHeaders(azimds.config.IMDSEndpoint+"/metadata/identity/oauth2/token", queryParams, headers)

	if err != nil {
		return r, errors.Wrapf(err, "http get authentication token failed")
	}

	httpResponseBodyBytes, err := httpResponseBody(httpResponse)
	if err != nil {
		return r, errors.Wrapf(err, "pulling http get authentication token response failed")
	}

	// Unmarshall response body into struct
	err = json.Unmarshal(httpResponseBodyBytes, &r)
	if err != nil {
		return r, errors.Wrapf(err, "unmarshalling authentication token response failed")
	}

	return r, nil
}

func httpResponseBody(httpResponse *http.Response) ([]byte, error) {
	if httpResponse.StatusCode != 200 {
		return nil, errors.Errorf("http response status equal to %s", httpResponse.Status)
	}

	// Pull out response body
	defer httpResponse.Body.Close()
	httpResponseBodyBytes, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "reading http response body failed")
	}

	return httpResponseBodyBytes, nil
}

func httpGetRequestWithCustomHeaders(uri string, queryParams url.Values, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "http get request creation failed")
	}

	req.URL.RawQuery = queryParams.Encode()

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	return httpClientDoRequest(req)
}

func httpClientDoRequest(req *http.Request) (*http.Response, error) {
	httpClientDoWrapper := func() (interface{}, error) {
		client := &http.Client{}
		return client.Do(req)
	}

	resp, err := httpClientDoWrapper()

	if err != nil {
		return nil, errors.Wrapf(err, "HTTP GET failed")
	}

	return resp.(*http.Response), nil
}

// fetchToken : Generates a token based on the config
func (azimds *azAuthIMDS) fetchToken(resourceId string) (*TokenResponse, error) {
	// Resource string is fixed and has no relation with any of the user inputs
	// This is not the resource URL, rather a way to identify the resource type and tenant
	// There are two options in the structure datalake and storage but datalake is not populated
	// and does not work in all types of clouds (US, German, China etc).

	// Call Identity sidecar and get the token.
	token, err := azimds.getTokenFromIdentitySidecar(resourceId, azimds.config.ArmId)
	return &token, err
}

type azAuthBlobIMDS struct {
	azAuthIMDS
}

// GetCredential : Get MSI based credentials for blob
func (azimds *azAuthBlobIMDS) getCredential() interface{} {
	// Generate the token based on configured inputs

	token, err := azimds.fetchToken(azure.PublicCloud.ResourceIdentifiers.Storage)
	if err != nil {
		// fmt.Println(token.AccessToken)
		log.Err("azAuthBlobIMDS::getCredential : Failed to get credential [%s]", err.Error())
		return nil
	}

	// Using token create the credential object, here also register a call back which refreshes the token
	tc := azblob.NewTokenCredential(token.AccessToken, func(tc azblob.TokenCredential) time.Duration {
		newToken, err := azimds.fetchToken(azure.PublicCloud.ResourceIdentifiers.Storage)
		if err != nil {
			log.Err("azAuthBlobIMDS::getCredential : Failed to refresh token [%s]", err.Error())
			return 0
		}

		// set the new token value
		tc.SetToken(newToken.AccessToken)
		log.Debug("azAuthBlobIMDS::getCredential : MSI Token retrieved %s (%s)", newToken.AccessToken, newToken.ExpiresOn.Format(time.RFC1123))

		// Get the next token slightly before the current one expires
		return time.Until(newToken.ExpiresOn) - 10*time.Second
	})

	return tc
}

type azAuthBfsIMDS struct {
	azAuthIMDS
}

// GetCredential : Get MSI based credentials for datalake
func (azimds *azAuthBfsIMDS) getCredential() interface{} {
	// Generate the token based on configured inputs
	token, err := azimds.fetchToken(azure.PublicCloud.ResourceIdentifiers.Datalake)
	if err != nil {
		// fmt.Println(token.AccessToken)
		log.Err("azAuthBfsIMDS::getCredential : Failed to get credential [%s]", err.Error())
		return nil
	}

	// Using token create the credential object, here also register a call back which refreshes the token
	tc := azbfs.NewTokenCredential(token.AccessToken, func(tc azbfs.TokenCredential) time.Duration {
		newToken, err := azimds.fetchToken(azure.PublicCloud.ResourceIdentifiers.Datalake)
		if err != nil {
			log.Err("azAuthBfsIMDS::getCredential : Failed to refresh token [%s]", err.Error())
			return 0
		}

		// set the new token value
		tc.SetToken(newToken.AccessToken)
		log.Debug("azAuthBfsIMDS::getCredential : MSI Token retrieved %s (%d)", newToken.AccessToken, newToken.ExpiresOn.Format(time.RFC1123))

		// Get the next token slightly before the current one expires
		return time.Until(newToken.ExpiresOn) - 10*time.Second
	})

	return tc
}
