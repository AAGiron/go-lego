package cmd

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"net/http"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	"github.com/urfave/cli/v2"
)

func createRun() *cli.Command {
	return &cli.Command{
		Name:  "run",
		Usage: "Register an account, then create and install a certificate",
		Before: func(ctx *cli.Context) error {
			// we require either domains or csr, but not both
			hasDomains := len(ctx.StringSlice("domains")) > 0
			hasCsr := len(ctx.String("csr")) > 0
			if hasDomains && hasCsr {
				log.Fatal("Please specify either --domains/-d or --csr/-c, but not both")
			}
			if !hasDomains && !hasCsr {
				log.Fatal("Please specify --domains/-d (or --csr/-c if you already have a CSR)")
			}
			return nil
		},
		Action: run,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "no-bundle",
				Usage: "Do not create a certificate bundle by adding the issuers certificate to the new certificate.",
			},
			&cli.BoolFlag{
				Name:  "must-staple",
				Usage: "Include the OCSP must staple TLS extension in the CSR and generated certificate. Only works if the CSR is generated by lego.",
			},
			&cli.StringFlag{
				Name:  "run-hook",
				Usage: "Define a hook. The hook is executed when the certificates are effectively created.",
			},
			&cli.StringFlag{
				Name:  "preferred-chain",
				Usage: "If the CA offers multiple certificate chains, prefer the chain with an issuer matching this Subject Common Name. If no match, the default offered chain will be used.",
			},
			&cli.StringFlag{
				Name:  "always-deactivate-authorizations",
				Usage: "Force the authorizations to be relinquished even if the certificate request was successful.",
			},
		},
	}
}

const rootPathWarningMessage = `!!!! HEADS UP !!!!

Your account credentials have been saved in your Let's Encrypt
configuration directory at "%s".

You should make a secure backup of this folder now. This
configuration directory will also contain certificates and
private keys obtained from Let's Encrypt so making regular
backups of this folder is ideal.
`

func run(ctx *cli.Context) error {
	if ctx.Bool("synclego") {
		// Wait for Pebble to be ready
		const expectedMessage = "pebble is ready"
		server, err := net.Listen("tcp", "127.0.0.1:9000")
		if err != nil {
			panic(err)
		}
		
		defer server.Close()	
		
		connection, err := server.Accept()
		if err != nil {
			panic(err)
		}
		
		buffer := make([]byte, len([]byte(expectedMessage)))
		
		_, err = connection.Read(buffer)
		if err != nil {
			panic(err)
		}

		if string(buffer) != expectedMessage {
			panic("received message does not match expected message")
		}
		connection.Close()

		// Pebble is ready, now we can proceed with the normal execution
	}

	//for testing the new challenge
	var pebbleRootCA []byte
	var pebbleerr error
	labelChallCSV := ""
	if ctx.Bool("newchallenge"){
		//we need the Root CA from Pebble's README.md:		
		pebbleRootCA, pebbleerr = getPebbleRootCA()
		if pebbleerr != nil {
			log.Fatalf("Could not complete Pebble's Root CA download:\n\t%v", pebbleerr)
		}

		labelChallCSV = "-new-challenge"
	}

	timer := time.Now
	startFullIssuance := timer()	

	accountsStorage := NewAccountsStorage(ctx)

	account, client := setup(ctx, accountsStorage)
	setupChallenges(ctx, client)

	if account.Registration == nil {
		reg, err := register(ctx, client)
		if err != nil {
			log.Fatalf("Could not complete registration\n\t%v", err)
		}

		account.Registration = reg
		if err = accountsStorage.Save(account); err != nil {
			log.Fatal(err)
		}

		fmt.Printf(rootPathWarningMessage, accountsStorage.GetRootPath())
		fmt.Println("Account ID:"+account.GetRegistration().URI)
	}else{
		if ctx.Bool("newchallenge"){
			//need a new account if we want to test PQC account keys (or do a roll-over)
			log.Fatalf("For the new challenge a new account (email) is required.")
		}
	}

	certsStorage := NewCertificatesStorage(ctx)
	certsStorage.CreateRootFolder()

	startRenewal := timer()	

	cert, err := obtainCertificate(ctx, client,certsStorage, pebbleRootCA)
	if err != nil {
		// Make sure to return a non-zero exit code if ObtainSANCertificate returned at least one error.
		// Due to us not returning partial certificate we can just exit here instead of at the end.
		log.Fatalf("Could not obtain certificates:\n\t%v", err)
	}
	
	fullIssuanceElapsedTime := timer().Sub(startFullIssuance)
	renewalElapsedTime := timer().Sub(startRenewal)
		
	if ctx.IsSet("timingcsv") {
		writeElapsedTime(float64(fullIssuanceElapsedTime)/float64(time.Millisecond), float64(renewalElapsedTime)/float64(time.Millisecond), ctx.String("wrapalgo"), ctx.String("certalgo")+labelChallCSV, ctx.String("timingcsv"))
	}
	
	certsStorage.SaveResource(cert)

	meta := map[string]string{
		renewEnvAccountEmail: account.Email,
		renewEnvCertDomain:   cert.Domain,
		renewEnvCertPath:     certsStorage.GetFileName(cert.Domain, ".crt"),
		renewEnvCertKeyPath:  certsStorage.GetFileName(cert.Domain, ".key"),
	}

	return launchHook(ctx.String("run-hook"), meta)
}

func handleTOS(ctx *cli.Context, client *lego.Client) bool {
	// Check for a global accept override
	if ctx.Bool("accept-tos") {
		return true
	}

	reader := bufio.NewReader(os.Stdin)
	log.Printf("Please review the TOS at %s", client.GetToSURL())

	for {
		fmt.Println("Do you accept the TOS? Y/n")
		text, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Could not read from console: %v", err)
		}

		text = strings.Trim(text, "\r\n")
		switch text {
		case "", "y", "Y":
			return true
		case "n", "N":
			return false
		default:
			fmt.Println("Your input was invalid. Please answer with one of Y/y, n/N or by pressing enter.")
		}
	}
}

func register(ctx *cli.Context, client *lego.Client) (*registration.Resource, error) {
	accepted := handleTOS(ctx, client)
	if !accepted {
		log.Fatal("You did not accept the TOS. Unable to proceed.")
	}

	if ctx.Bool("eab") {
		kid := ctx.String("kid")
		hmacEncoded := ctx.String("hmac")

		if kid == "" || hmacEncoded == "" {
			log.Fatalf("Requires arguments --kid and --hmac.")
		}

		return client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: accepted,
			Kid:                  kid,
			HmacEncoded:          hmacEncoded,
		})
	}

	return client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
}


//now adding 'certsStorage' and 'pebbleRootCA' for the newchallenge
func obtainCertificate(ctx *cli.Context, client *lego.Client, certsStorage  *CertificatesStorage, pebbleRootCA []byte) (*certificate.Resource, error) {
	api.PerformLoadTest = ctx.Bool("loadtestfinalize")
	api.NumThreads = ctx.Int("numthreads")
	api.LoadTestDurationSeconds = ctx.Int("loadtestduration")
	api.LoadTestCSVPath = ctx.String("loadtestcsv")
	api.CertAlgo = ctx.String("certalgo")
	api.WrapAlgo = ctx.String("wrapalgo")

	bundle := !ctx.Bool("no-bundle")

	domains := ctx.StringSlice("domains")
	if len(domains) > 0 {
		// obtain a certificate, generating a new private key
		request := certificate.ObtainRequest{
			Domains:                        domains,
			Bundle:                         bundle,
			MustStaple:                     ctx.Bool("must-staple"),
			PreferredChain:                 ctx.String("preferred-chain"),
			AlwaysDeactivateAuthorizations: ctx.Bool("always-deactivate-authorizations"),
			CertAlgorithm: 									certcrypto.KeyType(ctx.String("certalgo")),
			PKIELPData: certificate.PKIELPInfo{CertPSK: ctx.String("certpsk"), WrapAlgorithm: ctx.String("wrapalgo")},
		}
		//selects for new-challenge issuance
		if ctx.Bool("newchallenge"){
			//certsStoragePackaged := certsStorage.(certificate.CertificatesStorage)
			certsStoragePackaged := &certificate.CertificatesStorage{
					RootPath    :	certsStorage.rootPath,
					ArchivePath :	certsStorage.archivePath,
					Pem         :   certsStorage.pem,
					Pfx 		:   certsStorage.pfx,
					PfxPassword :	certsStorage.pfxPassword,
					Filename    :	certsStorage.filename, // Deprecated
					CertPSKID   :	certsStorage.certPSKID,
			} 
			return client.Certificate.TransitToPQC(request, ctx.String("server"), certsStoragePackaged, pebbleRootCA, ctx.String("certlabel"))
		}
		return client.Certificate.Obtain(request)
	}

	// read the CSR
	csr, err := readCSRFile(ctx.String("csr"))
	if err != nil {
		return nil, err
	}

	// obtain a certificate for this CSR
	//TODO: make the TransitToPQC case if a CSR is previously provided
	//if ctx.Bool("newchallenge"){
	return client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:                            csr,
		Bundle:                         bundle,
		PreferredChain:                 ctx.String("preferred-chain"),
		AlwaysDeactivateAuthorizations: ctx.Bool("always-deactivate-authorizations"),
	})
}



func writeElapsedTime(fullIssuanceElapsedTime, renewalElapsedTime float64, wrapAlgo, certAlgo, timingCSVPath string) {	

	var toWrite []string
	certAlgorithm := api.GetToBeIssuedCertificateAlgorithm(wrapAlgo, certAlgo)

	csvFile, err := os.OpenFile(timingCSVPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	csvwriter := csv.NewWriter(csvFile)
	csvReader := csv.NewReader(csvFile)
	_, err = csvReader.Read()	
	if err == io.EOF {
		toWrite = []string{"Certificate Public Key Algorithm", "Issuance time (ms)", "Renewal time (ms)"}
		if err := csvwriter.Write(toWrite); err != nil {
			log.Fatalf("error writing record to file. err: %s", err)
		}
	}

	toWrite = []string{certAlgorithm, fmt.Sprintf("%f", fullIssuanceElapsedTime), fmt.Sprintf("%f", renewalElapsedTime)}
	
	if err := csvwriter.Write(toWrite); err != nil {
		log.Fatalf("error writing record to file. err: %s", err)
	}
	
	csvwriter.Flush()
	csvFile.Close()
}


/*  Pebble's README.md: Note that the CA's root and intermediate certificates are regenerated on every
	launch. They can be retrieved by a `GET` request to `https://localhost:15000/roots/0`
	and `https://localhost:15000/intermediates/0` respectively.
*/
func getPebbleRootCA()([]byte, error){
	
	requestURL := "https://localhost:15000/roots/0"
	res, err := http.Get(requestURL)
	if err != nil {
		fmt.Printf("Error retrieving Pebble's Root CA: %s\n", err)
		return nil, err
	}

	rootCert, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Could not read response body for Pebble's Root CA: %s\n", err)
		return nil, err
	}

//	fmt.Printf("Root CA downloaded: %s\n", rootCert)
	return rootCert, nil
}