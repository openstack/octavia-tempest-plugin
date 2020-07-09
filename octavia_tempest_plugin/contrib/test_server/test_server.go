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
	"sync"
	"time"
)

var sess_cookie http.Cookie
var resp string

type ConnectionCount struct {
	mu         sync.Mutex
	cur_conn   int
	max_conn   int
	total_conn int
}

var scoreboard ConnectionCount

func (cc *ConnectionCount) open() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.cur_conn++
	cc.total_conn++
}

func (cc *ConnectionCount) close() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.cur_conn > cc.max_conn {
		cc.max_conn = cc.cur_conn
	}
	cc.cur_conn--
}

func (cc *ConnectionCount) stats() (int, int) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	return cc.max_conn, cc.total_conn
}

func (cc *ConnectionCount) reset() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.max_conn = 0
	cc.total_conn = 0
}

func root_handler(w http.ResponseWriter, r *http.Request) {
	scoreboard.open()
	defer scoreboard.close()

	http.SetCookie(w, &sess_cookie)
	io.WriteString(w, resp)
}

func slow_handler(w http.ResponseWriter, r *http.Request) {
	scoreboard.open()
	defer scoreboard.close()

	delay, err := time.ParseDuration(r.URL.Query().Get("delay"))
	if err != nil {
		delay = 3 * time.Second
	}

	time.Sleep(delay)
	http.SetCookie(w, &sess_cookie)
	io.WriteString(w, resp)
}

func stats_handler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &sess_cookie)
	max_conn, total_conn := scoreboard.stats()
	fmt.Fprintf(w, "max_conn=%d\ntotal_conn=%d\n", max_conn, total_conn)
}

func https_wrapper(base_handler func(http.ResponseWriter,
	*http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Add("Strict-Transport-Security",
			"max-age=66012000; includeSubDomains")
		base_handler(w, r)
	})
}

func reset_handler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &sess_cookie)
	scoreboard.reset()
	fmt.Fprintf(w, "reset\n")
}

func http_setup(id string) {
	sess_cookie.Name = "JSESSIONID"
	sess_cookie.Value = id

	http.HandleFunc("/", root_handler)
	http.HandleFunc("/slow", slow_handler)
	http.HandleFunc("/stats", stats_handler)
	http.HandleFunc("/reset", reset_handler)
}

func http_serve(port int, id string) {
	portStr := fmt.Sprintf(":%d", port)
	log.Fatal(http.ListenAndServe(portStr, nil))
}

func https_serve(port int, id string, cert tls.Certificate,
	certpool *x509.CertPool, server_cert_pem string,
	server_key_pem string) {
	mux := http.NewServeMux()
	mux.Handle("/", https_wrapper(root_handler))
	mux.Handle("/slow", https_wrapper(slow_handler))
	mux.Handle("/stats", https_wrapper(stats_handler))
	mux.Handle("/reset", https_wrapper(reset_handler))

	var tls_config *tls.Config
	if certpool != nil {
		tls_config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certpool,
			MinVersion:   tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384,
				tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
	} else {
		tls_config = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.NoClientCert,
			MinVersion:   tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384,
				tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
	}
	tls_config.Rand = rand.Reader
	portStr := fmt.Sprintf(":%d", port)
	srv := &http.Server{
		Addr:      portStr,
		Handler:   mux,
		TLSConfig: tls_config,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn,
			http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS(server_cert_pem, server_key_pem))
}

func udp_serve(port int, id string) {
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
	https_portPtr := flag.Int("https_port", -1,
		"HTTPS port to listen on, -1 is disabled.")
	server_cert_pem := flag.String("cert", "",
		"Server side PEM format certificate.")
	server_key := flag.String("key", "", "Server side PEM format key.")
	client_ca_cert_pem := flag.String("client_ca", "",
		"Client side PEM format CA certificate.")

	flag.Parse()

	resp = fmt.Sprintf("%s", *idPtr)

	http_setup(*idPtr)

	if *https_portPtr > -1 {
		cert, err := tls.LoadX509KeyPair(*server_cert_pem, *server_key)
		if err != nil {
			fmt.Println("Error load server certificate and key.\n")
			os.Exit(1)
		}
		certpool := x509.NewCertPool()
		if *client_ca_cert_pem != "" {
			ca_pem, err := ioutil.ReadFile(*client_ca_cert_pem)
			if err != nil {
				fmt.Println("Error load client side CA cert.\n")
				os.Exit(1)
			}
			if !certpool.AppendCertsFromPEM(ca_pem) {
				fmt.Println("Can't parse client side certificate authority")
				os.Exit(1)
			}
		} else {
			certpool = nil
		}
		go https_serve(*https_portPtr, *idPtr, cert, certpool,
			*server_cert_pem, *server_key)
	}

	go http_serve(*portPtr, *idPtr)
	udp_serve(*portPtr, *idPtr)
}
