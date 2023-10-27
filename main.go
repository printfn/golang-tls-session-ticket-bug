package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func generateCert() (*x509.CertPool, []tls.Certificate, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate rsa key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(30000000000000000),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:     x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{strings.Repeat("a", 18000)},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)
	chain := []tls.Certificate{
		{
			Certificate: [][]byte{rootDER},
			PrivateKey:  rootKey,
		},
	}
	err = os.WriteFile("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write cert file: %v", err)
	}
	err = os.WriteFile("key.pem", pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
	}), 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write cert file: %v", err)
	}
	return certPool, chain, nil
}

func readCert() (*x509.CertPool, []tls.Certificate, error) {
	certPEM, err := os.ReadFile("cert.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read cert: %v", err)
	}
	certDER, _ := pem.Decode(certPEM)
	if certDER == nil {
		return nil, nil, fmt.Errorf("failed to parse cert PEM: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse cert: %v", err)
	}
	keyPEM, err := os.ReadFile("key.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key: %v", err)
	}
	keyDER, _ := pem.Decode(keyPEM)
	if keyDER == nil {
		return nil, nil, fmt.Errorf("failed to parse key PEM: %v", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyDER.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse key: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	chain := []tls.Certificate{
		{
			Certificate: [][]byte{certDER.Bytes},
			PrivateKey:  key,
		},
	}
	return certPool, chain, nil
}

func foo() error {
	certPool, tlsCertificates, err := readCert()
	if err != nil {
		return fmt.Errorf("failed to generate certificates: %v", err)
	}
	server := http.Server{
		Addr: "127.0.0.1:8081",
		TLSConfig: &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: tlsCertificates,
			ClientCAs:    certPool,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("success"))
		}),
	}
	server.TLSConfig.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		// return []byte{0}, nil
		ticket, err := server.TLSConfig.EncryptTicket(cs, ss)
		if err != nil {
			fmt.Printf("failed to encrypt session ticket: %v\n", err)
			return nil, err
		}
		fmt.Printf("encrypted session ticket of length %d\n", len(ticket))
		return ticket, nil
	}
	server.TLSConfig.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		ss, err := server.TLSConfig.DecryptTicket(identity, cs)
		if err != nil {
			fmt.Printf("failed to decrypt session ticket: %v\n", err)
			return nil, err
		}
		fmt.Printf("decrypted session ticket of length %d\n", len(identity))
		return ss, nil
	}
	w, err := os.OpenFile("keys.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key log file: %v", err)
	}
	server.TLSConfig.KeyLogWriter = w
	fmt.Printf("listening...\n")
	server.ListenAndServeTLS("", "")
	/*go server.ListenAndServeTLS("", "")
	time.Sleep(time.Second)
	request, err := http.NewRequest("GET", "https://127.0.0.1:8081/", http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create http request: %v", err)
	}
	httpClient := http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := tls.Dial(network, addr, &tls.Config{
					RootCAs:            certPool,
					Certificates:       tlsCertificates,
					ClientSessionCache: tls.NewLRUClientSessionCache(0),
					MaxVersion:         tls.VersionTLS12,
				})
				return conn, err
			},
		},
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to make http request 1: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read body 1: %v", err)
	}
	fmt.Printf("body 1: %s\n", string(body))
	response2, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to make http request 2: %v", err)
	}
	body2, err := io.ReadAll(response2.Body)
	if err != nil {
		return fmt.Errorf("failed to read body 2: %v", err)
	}
	fmt.Printf("body 2: %s\n", string(body2))
	err = server.Close()
	if err != nil {
		return fmt.Errorf("failed to close server: %v", err)
	}*/
	return nil
}

func main() {
	err := foo()
	if err != nil {
		fmt.Printf("%v\n", err)
	}
}
