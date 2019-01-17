package main

import (
	"io/ioutil"
	"crypto/x509"
	"flag"
	"encoding/pem"
	"crypto/rsa"
)

//Convert DER-encoded private key(PKS1 or PKS8) to PEM-encoded PKS-1

var (
	fileInOpt = flag.String("i", "pk.der", "PK file in DER(binary format)")
	fileOutOpt   = flag.String("o", "pk.pem", "PK file in PEM(base64 format)")
)

func main()  {
	flag.Parse()

	der, err := ioutil.ReadFile(*fileInOpt)

	if err != nil {
		panic(err)
	}

	key, err := x509.ParsePKCS8PrivateKey(der)

	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(der)
	}

	if err != nil {
		panic(err)
	}

	rsaKey := key.(*rsa.PrivateKey)

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	ioutil.WriteFile(*fileOutOpt, pemdata, 0644)
}
