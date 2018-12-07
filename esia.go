package esia

import (
	"os"
	//"log"
	"io/ioutil"
	"net/http"
	"time"
	"fmt"
    "crypto/rand"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "encoding/json"
    "github.com/fullsailor/pkcs7"
    "net/url"
)

type ConfigOpenId struct {
    MnemonicsSystem string
    RedirectUrl string
    PortalUrl string
    PrivateKeyPath string
    PrivateKeyPassword string
    CertPath string
    TmpPath string
    Scope string
    CodeUrl string
    TokenUrl string
}

type EsiaToken struct {
    AccessToken string  `json:"access_token"`
    RefreshToken string  `json:"refresh_token"`
    State string  `json:"state"`
    TokenType string  `json:"token_type"`
    ExpiresIn int32 `json:"expires_in"`
}

type OpenId struct {
    Config ConfigOpenId
    AccessToken string
}

func (c *OpenId) GetState() (string, error){
    b := make([]byte, 16)
    _, err := rand.Read(b)
    if err != nil {
       return "", err
    }
    uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
       b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
    return uuid, nil
}

func (c *OpenId) GetTimeStamp() string {
      return time.Now().Format("2006.01.02 15:04:05 Z0700")
}

type requestTokenParams struct {
    client_id string ``
}

func (c *OpenId) GetUrl() (string, error){

    state, err := c.GetState()
    if err != nil {
        return "", err
    }

    timestamp := c.GetTimeStamp()
    clientSecret := c.Config.Scope + timestamp + c.Config.MnemonicsSystem + state
    clientSecret, err = c.Sign(clientSecret)
    if err != nil {
        return "", err
    }

    var Url *url.URL
    Url, err = url.Parse(c.Config.PortalUrl)
    if err != nil {
         return "", err
    }

    Url.Path += c.Config.CodeUrl

    params := &url.Values{
        "client_id": []string{c.Config.MnemonicsSystem},
        "client_secret": []string{clientSecret},
        "redirect_uri": []string{c.Config.RedirectUrl},
        "scope": []string{c.Config.Scope},
        "response_type": []string{"code"},
        "state": []string{state},
        "access_type": []string{"offline"},
        "timestamp": []string{timestamp},
    }

    Url.RawQuery = params.Encode()

    return Url.String(), nil
}

func (c *OpenId) GetInfoByPath() (string, error){

    state, err := c.GetState()
    if err != nil {
        return "", err
    }

    timestamp := c.GetTimeStamp()
    clientSecret := c.Config.Scope + timestamp + c.Config.MnemonicsSystem + state
    clientSecret, err = c.Sign(clientSecret)
    if err != nil {
        return "", err
    }

    var Url *url.URL
    Url, err = url.Parse(c.Config.PortalUrl)
    if err != nil {
         return "", err
    }

    Url.Path += c.Config.CodeUrl

    params := &url.Values{
        "client_id": []string{c.Config.MnemonicsSystem},
        "client_secret": []string{clientSecret},
        "redirect_uri": []string{c.Config.RedirectUrl},
        "scope": []string{c.Config.Scope},
        "response_type": []string{"code"},
        "state": []string{state},
        "access_type": []string{"offline"},
        "timestamp": []string{timestamp},
    }

    Url.RawQuery = params.Encode()

    return Url.String(), nil
}

func (c *OpenId) GetTokenState(code string) (EsiaToken, error){

    var esiaToken EsiaToken

    state, err := c.GetState()
    if err != nil {
        return esiaToken, err
    }

    timestamp := c.GetTimeStamp()
    clientSecret := c.Config.Scope + timestamp + c.Config.MnemonicsSystem + state
    clientSecret, err = c.Sign(clientSecret)
    if err != nil {
        return esiaToken, err
    }

    params := url.Values{
        "client_id": []string{c.Config.MnemonicsSystem},
        "code": []string{code},
        "grant_type": []string{"authorization_code"},
        "client_secret": []string{clientSecret},
        "state": []string{state},
        "redirect_uri": []string{c.Config.RedirectUrl},
        "scope": []string{c.Config.Scope},
        "timestamp": []string{timestamp},
        "token_type":[]string{"Bearer"},
        "refresh_token": []string{state},
    }
    resp, err := http.PostForm(c.Config.PortalUrl + c.Config.TokenUrl, params)
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return esiaToken, err
    }

    err = json.Unmarshal(body, &esiaToken)
    if err != nil {
        return esiaToken, err
    }

    //base64.RawURLEncoding.DecodeString(esiaToken)
    data, err := base64.StdEncoding.DecodeString(esiaToken.AccessToken)
    if err != nil {
        fmt.Println("error:", err)
        return esiaToken, err
    }
    fmt.Printf("%q\n", esiaToken.AccessToken)
    fmt.Printf("%q\n", data)

    c.AccessToken = esiaToken.AccessToken

    return esiaToken, nil
}

func (c *OpenId) Sign(message string) (string, error){

    privateKeyFile, err := os.Open(c.Config.PrivateKeyPath)
    defer privateKeyFile.Close()
    if err != nil {
        return "", err
    }
    privateKeyFileInfo, err := privateKeyFile.Stat()
    privateKeyFileSize := privateKeyFileInfo.Size()
    privateKeyBuffer := make([]byte, privateKeyFileSize)
    _, err = privateKeyFile.Read(privateKeyBuffer)
    if err != nil {
        return "", err
    }
    privateKeyBlock, _ := pem.Decode(privateKeyBuffer)
    privateKeyBufferParseResult, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)

    certFile, err := os.Open(c.Config.CertPath)
    defer certFile.Close()
    if err != nil {
        return "", err
    }
    certFileInfo, err := certFile.Stat()
    certFileSize := certFileInfo.Size()
    certBuffer := make([]byte, certFileSize)
    _, err = certFile.Read(certBuffer)
    if err != nil {
        return "", err
    }
    certBlock, _ := pem.Decode(certBuffer)
    certParseResult, err := x509.ParseCertificate(certBlock.Bytes)

	content := []byte(message)

    toBeSigned, err := pkcs7.NewSignedData(content)
    if err != nil {
         return "", err
    }

    if err := toBeSigned.AddSigner(certParseResult, privateKeyBufferParseResult, pkcs7.SignerInfoConfig{}); err != nil {
         return "", err
    }

    toBeSigned.Detach()
    signed, err := toBeSigned.Finish()
    if err != nil {
         return "", err
    }

    sig := base64.RawURLEncoding.EncodeToString(signed)

    return sig, nil
}
