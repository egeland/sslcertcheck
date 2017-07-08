/*
   SSL Cert Check - check your TLS certificates for imminent expiry.
   Copyright (C) 2017  Frode Egeland <egeland@gmail.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	r, err := regexp.Compile(`^CERT_`)
	if err != nil {
		fmt.Printf("There is a problem with your regexp.\n")
		return
	}
	prometheusURL := os.Getenv("PROMETHEUS")
	fmt.Printf("PROMETHEUS: %s\n", prometheusURL)
	warn, err := strconv.ParseFloat(os.Getenv("WARN"), 64)
	if err != nil {
		warn = 30
	}
	warn = math.Abs(warn)
	fmt.Printf("WARN LEVEL: %f\n", warn)
	env := os.Environ()
	var certURLs []string
	for _, value := range env {
		name := strings.Split(value, "=")
		if r.MatchString(name[0]) {
			certURLs = append(certURLs, name[1])
		}
	}
	fmt.Print("URLs: ")
	fmt.Println(certURLs)
	var okCerts []string
	var badCerts []string
	// Download certs
	pool, err := x509.SystemCertPool()
	if err != nil {
		fmt.Printf("Error %s loading system certs.\n", err)
		os.Exit(1)
	}
	if pool == nil {
		fmt.Println("No cert pools.")
		os.Exit(1)
	}
	for _, host := range certURLs {
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", host), &tls.Config{
			RootCAs:            pool,
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err != nil {
			fmt.Println("failed to connect: " + err.Error())
			badCerts = append(badCerts, host)
			continue
		}
		cert := conn.ConnectionState().PeerCertificates[0]
		expiry := cert.NotAfter
		fmt.Println(expiry.Local())
		// Check validity
		if err := cert.VerifyHostname(host); err != nil {
			fmt.Printf("ERROR: Cert for %s is invalid: ", host)
			fmt.Println(err)
			badCerts = append(badCerts, host)
			conn.Close()
			continue
		}
		okCerts = append(okCerts, host)
		conn.Close()
	}
	// Generate report in prometheus format
	fmt.Printf("OK: %s\n", okCerts)
	fmt.Printf("NG: %s\n", badCerts)
	// Send to prometheus
}
