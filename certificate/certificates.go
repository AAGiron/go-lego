package certificate

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"path/filepath"
	"github.com/go-acme/lego/v4/acme"	
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/platform/wait"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/idna"
)

// maxBodySize is the maximum size of body that we will read.
const maxBodySize = 1024 * 1024

// Resource represents a CA issued certificate.
// PrivateKey, Certificate and IssuerCertificate are all
// already PEM encoded and can be directly written to disk.
// Certificate may be a certificate bundle,
// depending on the options supplied to create it.
type Resource struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	PrivateKey        []byte `json:"-"`
	Certificate       []byte `json:"-"`
	IssuerCertificate []byte `json:"-"`
	CSR               []byte `json:"-"`
}

// ObtainRequest The request to obtain certificate.
//
// The first domain in domains is used for the CommonName field of the certificate,
// all other domains are added using the Subject Alternate Names extension.
//
// A new private key is generated for every invocation of the function Obtain.
// If you do not want that you can supply your own private key in the privateKey parameter.
// If this parameter is non-nil it will be used instead of generating a new one.
//
// If `Bundle` is true, the `[]byte` contains both the issuer certificate and your issued certificate as a bundle.
//
// If `AlwaysDeactivateAuthorizations` is true, the authorizations are also relinquished if the obtain request was successful.
// See https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.2.
type ObtainRequest struct {
	Domains                        []string
	Bundle                         bool
	PrivateKey                     crypto.PrivateKey
	MustStaple                     bool
	PreferredChain                 string
	AlwaysDeactivateAuthorizations bool
	CertAlgorithm			  	        certcrypto.KeyType	
}

// ObtainForCSRRequest The request to obtain a certificate matching the CSR passed into it.
//
// If `Bundle` is true, the `[]byte` contains both the issuer certificate and your issued certificate as a bundle.
//
// If `AlwaysDeactivateAuthorizations` is true, the authorizations are also relinquished if the obtain request was successful.
// See https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.2.
type ObtainForCSRRequest struct {
	CSR                            *x509.CertificateRequest
	Bundle                         bool
	PreferredChain                 string
	AlwaysDeactivateAuthorizations bool
}

type resolver interface {
	Solve(authorizations []acme.Authorization) error
}

type CertifierOptions struct {
	KeyType certcrypto.KeyType
	Timeout time.Duration
}

// Certifier A service to obtain/renew/revoke certificates.
type Certifier struct {
	core     *api.Core
	resolver resolver
	options  CertifierOptions
}

// NewCertifier creates a Certifier.
func NewCertifier(core *api.Core, resolver resolver, options CertifierOptions) *Certifier {
	return &Certifier{
		core:     core,
		resolver: resolver,
		options:  options,
	}
}

// Obtain tries to obtain a single certificate using all domains passed into it.
//
// This function will never return a partial certificate.
// If one domain in the list fails, the whole certificate will fail.
func (c *Certifier) Obtain(request ObtainRequest) (*Resource, error) {
	if len(request.Domains) == 0 {
		return nil, errors.New("no domains to obtain a certificate for")
	}

	domains := sanitizeDomain(request.Domains)

	if request.Bundle {
		log.Infof("[%s] acme: Obtaining bundled SAN certificate", strings.Join(domains, ", "))
	} else {
		log.Infof("[%s] acme: Obtaining SAN certificate", strings.Join(domains, ", "))
	}

	order, err := c.core.Orders.New(domains)
	if err != nil {
		return nil, err
	}

	authz, err := c.getAuthorizations(order)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		c.deactivateAuthorizations(order, request.AlwaysDeactivateAuthorizations)
		return nil, err
	}

	err = c.resolver.Solve(authz)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		c.deactivateAuthorizations(order, request.AlwaysDeactivateAuthorizations)
		return nil, err
	}

	log.Infof("[%s] acme: Validations succeeded; requesting certificates", strings.Join(domains, ", "))

	failures := make(obtainError)
	cert, err := c.getForOrder(domains, order, request.Bundle, request.PrivateKey, request.MustStaple, request.PreferredChain, request.CertAlgorithm)
	if err != nil {
		for _, auth := range authz {
			failures[challenge.GetTargetedDomain(auth)] = err
		}
	}

	if request.AlwaysDeactivateAuthorizations {
		c.deactivateAuthorizations(order, true)
	}

	// Do not return an empty failures map, because
	// it would still be a non-nil error value
	if len(failures) > 0 {
		return cert, failures
	}
	return cert, nil
}

// ObtainForCSR tries to obtain a certificate matching the CSR passed into it.
//
// The domains are inferred from the CommonName and SubjectAltNames, if any.
// The private key for this CSR is not required.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
//
// This function will never return a partial certificate.
// If one domain in the list fails, the whole certificate will fail.
func (c *Certifier) ObtainForCSR(request ObtainForCSRRequest) (*Resource, error) {
	if request.CSR == nil {
		return nil, errors.New("cannot obtain resource for CSR: CSR is missing")
	}

	// figure out what domains it concerns
	// start with the common name
	domains := certcrypto.ExtractDomainsCSR(request.CSR)

	if request.Bundle {
		log.Infof("[%s] acme: Obtaining bundled SAN certificate given a CSR", strings.Join(domains, ", "))
	} else {
		log.Infof("[%s] acme: Obtaining SAN certificate given a CSR", strings.Join(domains, ", "))
	}

	order, err := c.core.Orders.New(domains)
	if err != nil {
		return nil, err
	}

	authz, err := c.getAuthorizations(order)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		c.deactivateAuthorizations(order, request.AlwaysDeactivateAuthorizations)
		return nil, err
	}

	err = c.resolver.Solve(authz)
	if err != nil {
		// If any challenge fails, return. Do not generate partial SAN certificates.
		c.deactivateAuthorizations(order, request.AlwaysDeactivateAuthorizations)
		return nil, err
	}

	log.Infof("[%s] acme: Validations succeeded; requesting certificates", strings.Join(domains, ", "))

	failures := make(obtainError)
	cert, err := c.getForCSR(domains, order, request.Bundle, request.CSR.Raw, nil, request.PreferredChain)
	if err != nil {
		for _, auth := range authz {
			failures[challenge.GetTargetedDomain(auth)] = err
		}
	}

	if request.AlwaysDeactivateAuthorizations {
		c.deactivateAuthorizations(order, true)
	}

	if cert != nil {
		// Add the CSR to the certificate so that it can be used for renewals.
		cert.CSR = certcrypto.PEMEncode(request.CSR)
	}

	// Do not return an empty failures map,
	// because it would still be a non-nil error value
	if len(failures) > 0 {
		return cert, failures
	}
	return cert, nil
}

func (c *Certifier) getForOrder(domains []string, order acme.ExtendedOrder, bundle bool, privateKey crypto.PrivateKey, mustStaple bool, preferredChain string, certAlgorithm certcrypto.KeyType) (*Resource, error) {
	if privateKey == nil {
		var err error
		privateKey, err = certcrypto.GeneratePrivateKey(certAlgorithm)
		if err != nil {
			return nil, err
		}
	}

	// Determine certificate name(s) based on the authorization resources
	commonName := domains[0]

	// RFC8555 Section 7.4 "Applying for Certificate Issuance"
	// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
	// says:
	//   Clients SHOULD NOT make any assumptions about the sort order of
	//   "identifiers" or "authorizations" elements in the returned order
	//   object.
	san := []string{commonName}
	for _, auth := range order.Identifiers {
		if auth.Value != commonName {
			san = append(san, auth.Value)
		}
	}

	var csr []byte
	var err error

	csr, err = certcrypto.GenerateCSR(privateKey, commonName, san, mustStaple)
		
	if err != nil {
		return nil, err
	}

	return c.getForCSR(domains, order, bundle, csr, certcrypto.PEMEncode(privateKey), preferredChain)
}

func (c *Certifier) getForCSR(domains []string, order acme.ExtendedOrder, bundle bool, csr, privateKeyPem []byte, preferredChain string) (*Resource, error) {
	respOrder, err := c.core.Orders.UpdateForCSR(order.Finalize, csr)
	if err != nil {
		return nil, err
	}

	commonName := domains[0]
	certRes := &Resource{
		Domain:     commonName,
		CertURL:    respOrder.Certificate,
		PrivateKey: privateKeyPem,
	}

	if respOrder.Status == acme.StatusValid {
		// if the certificate is available right away, short cut!
		ok, errR := c.checkResponse(respOrder, certRes, bundle, preferredChain)
		if errR != nil {
			return nil, errR
		}

		if ok {
			return certRes, nil
		}
	}

	timeout := c.options.Timeout
	if c.options.Timeout <= 0 {
		timeout = 30 * time.Second
	}

	err = wait.For("certificate", timeout, timeout/60, func() (bool, error) {
		ord, errW := c.core.Orders.Get(order.Location)
		if errW != nil {
			return false, errW
		}

		done, errW := c.checkResponse(ord, certRes, bundle, preferredChain)
		if errW != nil {
			return false, errW
		}

		return done, nil
	})

	return certRes, err
}

// checkResponse checks to see if the certificate is ready and a link is contained in the response.
//
// If so, loads it into certRes and returns true.
// If the cert is not yet ready, it returns false.
//
// The certRes input should already have the Domain (common name) field populated.
//
// If bundle is true, the certificate will be bundled with the issuer's cert.
func (c *Certifier) checkResponse(order acme.ExtendedOrder, certRes *Resource, bundle bool, preferredChain string) (bool, error) {
	valid, err := checkOrderStatus(order)
	if err != nil || !valid {
		return valid, err
	}

	certs, err := c.core.Certificates.GetAll(order.Certificate, bundle)
	if err != nil {
		return false, err
	}

	// Set the default certificate
	certRes.IssuerCertificate = certs[order.Certificate].Issuer
	certRes.Certificate = certs[order.Certificate].Cert
	certRes.CertURL = order.Certificate
	certRes.CertStableURL = order.Certificate

	if preferredChain == "" {
		log.Infof("[%s] Server responded with a certificate.", certRes.Domain)

		return true, nil
	}

	for link, cert := range certs {
		ok, err := hasPreferredChain(cert.Issuer, preferredChain)
		if err != nil {
			return false, err
		}

		if ok {
			log.Infof("[%s] Server responded with a certificate for the preferred certificate chains %q.", certRes.Domain, preferredChain)

			certRes.IssuerCertificate = cert.Issuer
			certRes.Certificate = cert.Cert
			certRes.CertURL = link
			certRes.CertStableURL = link

			return true, nil
		}
	}

	log.Infof("lego has been configured to prefer certificate chains with issuer %q, but no chain from the CA matched this issuer. Using the default certificate chain instead.", preferredChain)

	return true, nil
}

// Revoke takes a PEM encoded certificate or bundle and tries to revoke it at the CA.
func (c *Certifier) Revoke(cert []byte) error {
	return c.RevokeWithReason(cert, nil)
}

// RevokeWithReason takes a PEM encoded certificate or bundle and tries to revoke it at the CA.
func (c *Certifier) RevokeWithReason(cert []byte, reason *uint) error {
	certificates, err := certcrypto.ParsePEMBundle(cert)
	if err != nil {
		return err
	}

	x509Cert := certificates[0]
	if x509Cert.IsCA {
		return errors.New("certificate bundle starts with a CA certificate")
	}

	revokeMsg := acme.RevokeCertMessage{
		Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw),
		Reason:      reason,
	}

	return c.core.Certificates.Revoke(revokeMsg)
}

// Renew takes a Resource and tries to renew the certificate.
//
// If the renewal process succeeds, the new certificate will be returned in a new CertResource.
// Please be aware that this function will return a new certificate in ANY case that is not an error.
// If the server does not provide us with a new cert on a GET request to the CertURL
// this function will start a new-cert flow where a new certificate gets generated.
//
// If bundle is true, the []byte contains both the issuer certificate and your issued certificate as a bundle.
//
// For private key reuse the PrivateKey property of the passed in Resource should be non-nil.
func (c *Certifier) Renew(certRes Resource, bundle, mustStaple bool, preferredChain string) (*Resource, error) {
	// Input certificate is PEM encoded.
	// Decode it here as we may need the decoded cert later on in the renewal process.
	// The input may be a bundle or a single certificate.
	certificates, err := certcrypto.ParsePEMBundle(certRes.Certificate)
	if err != nil {
		return nil, err
	}

	x509Cert := certificates[0]
	if x509Cert.IsCA {
		return nil, fmt.Errorf("[%s] Certificate bundle starts with a CA certificate", certRes.Domain)
	}

	// This is just meant to be informal for the user.
	timeLeft := x509Cert.NotAfter.Sub(time.Now().UTC())
	log.Infof("[%s] acme: Trying renewal with %d hours remaining", certRes.Domain, int(timeLeft.Hours()))

	// We always need to request a new certificate to renew.
	// Start by checking to see if the certificate was based off a CSR,
	// and use that if it's defined.
	if len(certRes.CSR) > 0 {
		csr, errP := certcrypto.PemDecodeTox509CSR(certRes.CSR)
		if errP != nil {
			return nil, errP
		}

		return c.ObtainForCSR(ObtainForCSRRequest{
			CSR:            csr,
			Bundle:         bundle,
			PreferredChain: preferredChain,
		})
	}

	var privateKey crypto.PrivateKey
	if certRes.PrivateKey != nil {
		privateKey, err = certcrypto.ParsePEMPrivateKey(certRes.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	query := ObtainRequest{
		Domains:        certcrypto.ExtractDomains(x509Cert),
		Bundle:         bundle,
		PrivateKey:     privateKey,
		MustStaple:     mustStaple,
		PreferredChain: preferredChain,
	}
	return c.Obtain(query)
}

// GetOCSP takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any.
//
// The returned []byte can be passed directly into the OCSPStaple property of a tls.Certificate.
// If the bundle only contains the issued certificate,
// this function will try to get the issuer certificate from the IssuingCertificateURL in the certificate.
//
// If the []byte and/or ocsp.Response return values are nil, the OCSP status may be assumed OCSPUnknown.
func (c *Certifier) GetOCSP(bundle []byte) ([]byte, *ocsp.Response, error) {
	certificates, err := certcrypto.ParsePEMBundle(bundle)
	if err != nil {
		return nil, nil, err
	}

	// We expect the certificate slice to be ordered downwards the chain.
	// SRV CRT -> CA. We need to pull the leaf and issuer certs out of it,
	// which should always be the first two certificates.
	// If there's no OCSP server listed in the leaf cert, there's nothing to do.
	// And if we have only one certificate so far, we need to get the issuer cert.

	issuedCert := certificates[0]

	if len(issuedCert.OCSPServer) == 0 {
		return nil, nil, errors.New("no OCSP server specified in cert")
	}

	if len(certificates) == 1 {
		// TODO: build fallback. If this fails, check the remaining array entries.
		if len(issuedCert.IssuingCertificateURL) == 0 {
			return nil, nil, errors.New("no issuing certificate URL")
		}

		resp, errC := c.core.HTTPClient.Get(issuedCert.IssuingCertificateURL[0])
		if errC != nil {
			return nil, nil, errC
		}
		defer resp.Body.Close()

		issuerBytes, errC := io.ReadAll(http.MaxBytesReader(nil, resp.Body, maxBodySize))
		if errC != nil {
			return nil, nil, errC
		}

		issuerCert, errC := x509.ParseCertificate(issuerBytes)
		if errC != nil {
			return nil, nil, errC
		}

		// Insert it into the slice on position 0
		// We want it ordered right SRV CRT -> CA
		certificates = append(certificates, issuerCert)
	}

	issuerCert := certificates[1]

	// Finally kick off the OCSP request.
	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := c.core.HTTPClient.Post(issuedCert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(ocspReq))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	ocspResBytes, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, maxBodySize))
	if err != nil {
		return nil, nil, err
	}

	ocspRes, err := ocsp.ParseResponse(ocspResBytes, issuerCert)
	if err != nil {
		return nil, nil, err
	}

	return ocspResBytes, ocspRes, nil
}

// Get attempts to fetch the certificate at the supplied URL.
// The URL is the same as what would normally be supplied at the Resource's CertURL.
//
// The returned Resource will not have the PrivateKey and CSR fields populated as these will not be available.
//
// If bundle is true, the Certificate field in the returned Resource includes the issuer certificate.
func (c *Certifier) Get(url string, bundle bool) (*Resource, error) {
	cert, issuer, err := c.core.Certificates.Get(url, bundle)
	if err != nil {
		return nil, err
	}

	// Parse the returned cert bundle so that we can grab the domain from the common name.
	x509Certs, err := certcrypto.ParsePEMBundle(cert)
	if err != nil {
		return nil, err
	}

	return &Resource{
		Domain:            x509Certs[0].Subject.CommonName,
		Certificate:       cert,
		IssuerCertificate: issuer,
		CertURL:           url,
		CertStableURL:     url,
	}, nil
}

func hasPreferredChain(issuer []byte, preferredChain string) (bool, error) {
	certs, err := certcrypto.ParsePEMBundle(issuer)
	if err != nil {
		return false, err
	}

	topCert := certs[len(certs)-1]

	if topCert.Issuer.CommonName == preferredChain {
		return true, nil
	}

	return false, nil
}

func checkOrderStatus(order acme.ExtendedOrder) (bool, error) {
	switch order.Status {
	case acme.StatusValid:
		return true, nil
	case acme.StatusInvalid:
		return false, order.Error
	default:
		return false, nil
	}
}

// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.4
// The domain name MUST be encoded in the form in which it would appear in a certificate.
// That is, it MUST be encoded according to the rules in Section 7 of [RFC5280].
//
// https://www.rfc-editor.org/rfc/rfc5280.html#section-7
func sanitizeDomain(domains []string) []string {
	var sanitizedDomains []string
	for _, domain := range domains {
		sanitizedDomain, err := idna.ToASCII(domain)
		if err != nil {
			log.Infof("skip domain %q: unable to sanitize (punnycode): %v", domain, err)
		} else {
			sanitizedDomains = append(sanitizedDomains, sanitizedDomain)
		}
	}
	return sanitizedDomains
}


//Can not import from cert_storage, so I need the struct and ReadResource function...
type CertificatesStorage struct {
	RootPath    string
	ArchivePath string
	Pem         bool
	Pfx         bool
	PfxPassword string
	Filename    string // Deprecated
	CertPSKID   string
}

// TransitToPQC tries to obtain a single certificate using all domains passed into it (just like Obtain)
// however, it uses the 'new challenge'. In summary:
//			Gets domains from request and retrieves previously issued certificate, 
//			make an auth. POST to Pebble's /pq-order
//			including a CSR in that POST
//			if ok, then post-as-get to download certificate
// Requirement: a previously generated certificate for the TLS client auth (tries to retrieve from storage)
func (c *Certifier) TransitToPQC(request ObtainRequest, serverURL string, storage *CertificatesStorage, certlabel string) (*Resource, error){

	if len(request.Domains) == 0 {
		return nil, errors.New("no domains to obtain a certificate for")
	}

	domains := sanitizeDomain(request.Domains)	
	var acmeID []acme.Identifier
	for _, domain := range domains {
		acmeID = append(acmeID, acme.Identifier{Type: "dns", Value: domain})
	}

	if request.Bundle {
		log.Infof("[%s] acme: Obtaining bundled SAN certificate", strings.Join(domains, ", "))
	} else {
		log.Infof("[%s] acme: Obtaining SAN certificate", strings.Join(domains, ", "))
	}

	//creates a CSR (TODO: could make the pre-computed CSR case)
	commonName := domains[0]
	//var err error
	privateKey, err := certcrypto.GeneratePrivateKey(request.CertAlgorithm)
	if err != nil {
		return nil, err
	}
	
	//from getForOrder
	san := []string{commonName}
	csr, err := certcrypto.GenerateCSR(privateKey, commonName, san, request.MustStaple)

	//create a acme.PQOrderMessage
	requestMessage := acme.PQOrderMessage{
		Identifiers: acmeID,
		Csr:		 base64.RawURLEncoding.EncodeToString(csr),
	}

	//server URL is https://127.0.0.1:14000/dir but I need the host (maybe do this separate function here)
	sURLsubstr := strings.Split(serverURL,":")
	serverHost := sURLsubstr[0] + ":" + sURLsubstr[1]
	pqOrderURL := serverHost+":10001/pq-order"

	//post /pq-order (TODO: port number is hardcoded. Change that)
	log.Infof("[%s] acme (new challenge): Making TLS-Auth. POST request to: "+pqOrderURL, commonName)
	httpReply, posterr := c.TLSMutualAuthPostHandler(pqOrderURL, domains[0], requestMessage, storage)	
	if posterr != nil {
		return nil, posterr
	}
	log.Infof("[%s] acme (new challenge): TLS-Auth. POST Status Valid.", commonName)
	defer httpReply.Body.Close()

	//little parsing without creating a struct (TODO: create a struct)
	//ioReply, err := io.ReadAll(httpReply.Body)
	var replydata map[string]interface{}
	//var replydata interface{}    
    //jsonerr := json.Unmarshal([]byte(ioReply), &replydata)
    jsonerr := json.NewDecoder(httpReply.Body).Decode(&replydata)
    if jsonerr != nil {
        return nil, jsonerr
    }

	//if ok, calls Get (defined above) to the cert URL
	var url string
	//fmt.Println(replydata)
	if replydata["certificate"] != "" { //if JSON-like reply
		url, _ = replydata["certificate"].(string)
	}
	
	log.Infof("[%s] acme (new challenge): Downloading certificate from: "+url, commonName)
	certPQCResource, downerr := c.Get(url, request.Bundle) //if url is null Get() handles it
	if downerr != nil {
		return nil, downerr
	}

	return certPQCResource, nil
}


//POST request. A better place for this would be at the sender.go (although we need things from api.go)
//It takes an endpoint (check if Pebble is advertising it, currently it is hardcoded in the caller function)
//the cert resource is used to read private key and certificate to the TLS handshake (with client auth)
//If the handshake is established, confirms the POST and returns the http response 
//If not, Pebble will not issue the (new and PQC) certificate
//code based on api.go
func (c *Certifier) TLSMutualAuthPostHandler(endpoint string, domain string, requestMessage acme.PQOrderMessage, storage *CertificatesStorage) (*http.Response, error){
	//create JWS request obj	
	content, err := json.Marshal(requestMessage)
	if err != nil {
		return nil, err
	}
	//sign JWS	
	signedContent, signerr := c.core.Jws.SignContent(endpoint, content)
	if signerr != nil {
		return nil, signerr
	}

	signedBody := bytes.NewBuffer([]byte(signedContent.FullSerialize()))

	//TLS preparation - Setup HTTPS client (read client cert and root CA)
	filename := sanitizedDomain(domain) + ".crt"
	keyname := sanitizedDomain(domain) + ".key"
	certFile := filepath.Join(storage.RootPath+"/", filename)
	keyFile := filepath.Join(storage.RootPath+"/", keyname)


	clientCert, lerr := tls.LoadX509KeyPair(certFile, keyFile)
	if lerr != nil {
        return nil, lerr
    }

	//TLS Client Configuration
	tlsConfig := &tls.Config{
		MinVersion:                 tls.VersionTLS13,
		MaxVersion:                 tls.VersionTLS13,
		InsecureSkipVerify:         false,
		SupportDelegatedCredential: false,
		Certificates: 				[]tls.Certificate{clientCert},
	}
	//fmt.Println(tlsConfig.Certificates)
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	
	////POST: make our post ;charset=UTF-8
	resp, tlserr := client.Post(endpoint, "application/jose+json", signedBody)
	if tlserr != nil {
		return nil, tlserr
	}

	if resp.Status == "200 OK" {	
		//export this?
		// nonceErr is ignored to keep the root error. (actually we are disabling it in Pebble...)
		nonce, nonceErr := GetNonceFromResponse(resp)
		if nonceErr == nil {
			c.core.NonceManager.Push(nonce)
		}
		//returns response		
		return resp, nil
	}else{
		log.Fatalf("PQ-Order reply gives HTTP error code:%v", resp.Status)
	}

	return nil,tlserr
}


// GetFromResponse Extracts a nonce from a HTTP response (from nonce_manager.go, but it is internal package).
func GetNonceFromResponse(resp *http.Response) (string, error) {
	if resp == nil {
		return "", errors.New("nil response")
	}

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", errors.New("server did not respond with a proper nonce header")
	}

	return nonce, nil
}

// sanitizedDomain is also from certs_storage.go
func sanitizedDomain(domain string) string {
	safe, err := idna.ToASCII(strings.ReplaceAll(domain, "*", "_"))
	if err != nil {
		log.Fatal(err)
	}
	return safe
}
