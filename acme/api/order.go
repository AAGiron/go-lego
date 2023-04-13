package api

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"crypto"
)

var PerformLoadTest bool
var NumThreads int
var LoadTestDurationSeconds int
var LoadTestCSVPath, CertAlgo string
var GenCSRatLoadTest bool
var PQOrderEndpoint string

type OrderService service

// New Creates a new order.
func (o *OrderService) New(domains []string) (acme.ExtendedOrder, error) {
	var identifiers []acme.Identifier
	for _, domain := range domains {
		identifiers = append(identifiers, acme.Identifier{Type: "dns", Value: domain})
	}

	orderReq := acme.Order{Identifiers: identifiers}

	var order acme.Order
	resp, err := o.core.post(o.core.GetDirectory().NewOrderURL, orderReq, &order)
	if err != nil {
		return acme.ExtendedOrder{}, err
	}

	return acme.ExtendedOrder{
		Order:    order,
		Location: resp.Header.Get("Location"),
	}, nil
}

// Get Gets an order.
func (o *OrderService) Get(orderURL string) (acme.ExtendedOrder, error) {
	if orderURL == "" {
		return acme.ExtendedOrder{}, errors.New("order[get]: empty URL")
	}

	var order acme.Order
	_, err := o.core.postAsGet(orderURL, &order)
	if err != nil {
		return acme.ExtendedOrder{}, err
	}

	return acme.ExtendedOrder{Order: order}, nil
}

// UpdateForCSR Updates an order for a CSR.
func (o *OrderService) UpdateForCSR(orderURL string, csr []byte) (acme.ExtendedOrder, error) {
	csrMsg := acme.CSRMessage{
		Csr: base64.RawURLEncoding.EncodeToString(csr),
	}

	var order acme.Order

	if PerformLoadTest {
		c := make(chan int)		
		successfulRequests := 0

		for i := 0; i < NumThreads; i++ {
			go o.testFinalizeOrder(orderURL, csrMsg, &order, c)
		}
		
		for i := 0; i < NumThreads; i++ {
			successfulRequests = successfulRequests + <-c
		}

		if LoadTestCSVPath != "" {
			if err := writeLoadTestResults(successfulRequests); err != nil {
				panic(err)
			}
		}

		fmt.Printf("Successfull requests: %d\n", successfulRequests)
	}

	_, err := o.core.post(orderURL, csrMsg, &order)
	if err != nil {
		return acme.ExtendedOrder{}, err
	}

	if order.Status == acme.StatusInvalid {
		return acme.ExtendedOrder{}, order.Error
	}

	return acme.ExtendedOrder{Order: order}, nil
}

func (o *OrderService) testFinalizeOrder(orderURL string, csrMsg acme.CSRMessage, order *acme.Order, c chan int) {
	// numRequests := 30	
	successfulRequests := 0

	// for i := 0; i < numRequests; i++ {
	// 	resp, err := o.core.post(orderURL, csrMsg, order)		
	// 	if err != nil {
	// 		continue
	// 	}	
	// 	if order.Status == acme.StatusInvalid {
	// 		continue
	// 	}
	// 	if resp.StatusCode != 200 {
	// 		continue
	// 	}

	// 	successfulRequests = successfulRequests + 1
	// }
	
	loop:
    for timeout := time.After(time.Duration(LoadTestDurationSeconds)*time.Second); ; {
			select {
			case <-timeout:
				break loop
			default:
			}
			
			//test impacts of including CSR crypto operations
			if GenCSRatLoadTest {
				var privateKey crypto.PrivateKey
				var err error
				privateKey, err = certcrypto.GeneratePrivateKey(certcrypto.KeyType(CertAlgo))
				if err != nil {
					panic(err)
				}

				san := []string{"teste"}
				for _, auth := range order.Identifiers {
					if auth.Value != "teste" {
						san = append(san, auth.Value)
					}
				}

//				var csr []byte
				_, err = certcrypto.GenerateCSR(privateKey, "teste", san, true)
			}

			resp, err := o.core.post(orderURL, csrMsg, order)		
			if err != nil {
				continue
			}	
			if order.Status == acme.StatusInvalid {
				continue
			}
			if resp.StatusCode != 200 {
				continue
			}

			successfulRequests = successfulRequests + 1
    }

	c <- successfulRequests
	// fmt.Printf("Successfull requests: %d\n", successfulRequests)
}

func writeLoadTestResults(successfulRequests int) error {

	var toWrite []string
	certAlgorithm := GetToBeIssuedCertificateAlgorithm(CertAlgo)

	csvFile, err := os.OpenFile(LoadTestCSVPath, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err	
	}

	csvwriter := csv.NewWriter(csvFile)
	csvReader := csv.NewReader(csvFile)
	_, err = csvReader.Read()	
	if err == io.EOF {
		toWrite = []string{"Certificate Public Key Algorithm", "Successful Requests"}
		if err := csvwriter.Write(toWrite); err != nil {
			return err
		}
	}

	toWrite = []string{certAlgorithm, strconv.Itoa(successfulRequests)}
	
	if err := csvwriter.Write(toWrite); err != nil {
		return err
	}
	
	csvwriter.Flush()
	csvFile.Close()
	return nil
}

func GetToBeIssuedCertificateAlgorithm(certAlgo string) string {
	if certAlgo == "P256" || certAlgo == "P384" || certAlgo == "P521" {
		return "ECDSA_" + certAlgo
	}	else {  // post-quantum algorithm
		return certAlgo
	}
}