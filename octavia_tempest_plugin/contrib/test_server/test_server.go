package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

var sessCookie http.Cookie
var resp string

type connectionCount struct {
	mu        sync.Mutex
	curConn   int
	maxConn   int
	totalConn int
}

var scoreboard connectionCount

func (cc *connectionCount) open() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.curConn++
	cc.totalConn++
}

func (cc *connectionCount) close() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.curConn > cc.maxConn {
		cc.maxConn = cc.curConn
	}
	cc.curConn--
}

func (cc *connectionCount) stats() (int, int) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return cc.maxConn, cc.totalConn
}

func (cc *connectionCount) reset() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.maxConn = 0
	cc.totalConn = 0
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	scoreboard.open()
	defer scoreboard.close()

	http.SetCookie(w, &sessCookie)
	io.WriteString(w, resp)
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	scoreboard.open()
	defer scoreboard.close()

	http.SetCookie(w, &sessCookie)

	params := r.URL.Query()
	if value, ok := params["response_code"]; ok {
		if responseCode, err := strconv.Atoi(value[0]); err == nil {
			w.WriteHeader(responseCode)
		}
	}

	io.WriteString(w, fmt.Sprintf("%s %s %s\n",
	                              r.Method, r.RequestURI, r.Proto))

	io.WriteString(w, fmt.Sprintf("Host: %s\n", r.Host))

	for key, values := range r.Header {
		for _, value := range values {
			header := fmt.Sprintf("%s: %s\n", key, value)
			io.WriteString(w, header)
		}
	}
	io.WriteString(w, "\n")
	io.WriteString(w, resp)
}

func slowHandler(w http.ResponseWriter, r *http.Request) {
	scoreboard.open()
	defer scoreboard.close()

	delay, err := time.ParseDuration(r.URL.Query().Get("delay"))
	if err != nil {
		delay = 3 * time.Second
	}

	time.Sleep(delay)
	http.SetCookie(w, &sessCookie)
	io.WriteString(w, resp)
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &sessCookie)
	maxConn, totalConn := scoreboard.stats()
	fmt.Fprintf(w, "maxConn=%d\ntotalConn=%d\n", maxConn, totalConn)
}

func httpsWrapper(baseHandler func(http.ResponseWriter,
	*http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Add("Strict-Transport-Security",
			"max-age=66012000; includeSubDomains")
		baseHandler(w, r)
	})
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &sessCookie)
	scoreboard.reset()
	fmt.Fprintf(w, "reset\n")
}

func httpSetup(id string) {
	sessCookie.Name = "JSESSIONID"
	sessCookie.Value = id

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/slow", slowHandler)
	http.HandleFunc("/stats", statsHandler)
	http.HandleFunc("/reset", resetHandler)
	http.HandleFunc("/request", requestHandler)
}

func httpServe(port int, id string) {
	portStr := fmt.Sprintf(":%d", port)
	log.Fatal(http.ListenAndServe(portStr, nil))
}

func httpsServe(port int, id string, cert tls.Certificate,
	certpool *x509.CertPool, serverCertPem string,
	serverKeyPem string) {
	mux := http.NewServeMux()
	mux.Handle("/", httpsWrapper(rootHandler))
	mux.Handle("/slow", httpsWrapper(slowHandler))
	mux.Handle("/stats", httpsWrapper(statsHandler))
	mux.Handle("/reset", httpsWrapper(resetHandler))
	mux.Handle("/request", httpsWrapper(requestHandler))

	var tlsConfig *tls.Config
	if certpool != nil {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certpool,
			MinVersion:   tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384,
				tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			NextProtos: []string{"h2", "http/1.1", "http/1.0"},
		}
	} else {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
			MinVersion:   tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384,
				tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			NextProtos: []string{"h2", "http/1.1", "http/1.0"},
		}
	}
	tlsConfig.Rand = rand.Reader
	portStr := fmt.Sprintf(":%d", port)
	srv := &http.Server{
		Addr:      portStr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}
	log.Fatal(srv.ListenAndServeTLS(serverCertPem, serverKeyPem))
}

func udpServe(port int, id string) {
	portStr := fmt.Sprintf("0.0.0.0:%d", port)

	pc, err := net.ListenPacket("udp", portStr)
	if err != nil {
		fmt.Println(err)
		return
	}

	buffer := make([]byte, 1500)

	for {
		_, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			fmt.Println(err)
			return
		}
		_, err = pc.WriteTo([]byte(resp), addr)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func main() {
	portPtr := flag.Int("port", 8080, "Port to listen on")
	idPtr := flag.String("id", "1", "Server ID")
	httpsPortPtr := flag.Int("https_port", -1,
		"HTTPS port to listen on, -1 is disabled.")
	httpsClientAuthPortPtr := flag.Int("https_client_auth_port", -1,
		"HTTPS with client authentication port to listen on, -1 is disabled.")
	serverCertPem := flag.String("cert", "",
		"Server side PEM format certificate file path.")
	serverKey := flag.String("key", "",
        "Server side PEM format key file path.")
	clientCaCertPem := flag.String("client_ca", "",
		"Client auth PEM format CA certificate file path.")

	flag.Parse()

	resp = fmt.Sprintf("%s", *idPtr)

	httpSetup(*idPtr)

	if *httpsPortPtr > -1 {
		cert, err := tls.LoadX509KeyPair(*serverCertPem, *serverKey)
		if err != nil {
			fmt.Println("Error load server certificate and key.")
			os.Exit(1)
		}
		go httpsServe(*httpsPortPtr, *idPtr, cert, nil,
			*serverCertPem, *serverKey)
	}

	if *httpsClientAuthPortPtr > -1 {
		cert, err := tls.LoadX509KeyPair(*serverCertPem, *serverKey)
		if err != nil {
			fmt.Println("Error load server certificate and key.\n")
			os.Exit(1)
		}
		certpool := x509.NewCertPool()
		caPem, err := ioutil.ReadFile(*clientCaCertPem)
		if err != nil {
			fmt.Println("Error loading client auth CA cert.\n")
			os.Exit(1)
		}
		if !certpool.AppendCertsFromPEM(caPem) {
			fmt.Println("Can't parse client auth certificate authority")
			os.Exit(1)
		}
		go httpsServe(*httpsClientAuthPortPtr, *idPtr, cert, certpool,
			*serverCertPem, *serverKey)
	}

	go httpServe(*portPtr, *idPtr)
	udpServe(*portPtr, *idPtr)
}
