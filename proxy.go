package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listeners   []ListenerConfig `yaml:"listeners"`
	Users       []User           `yaml:"users"`
	TLSEnabled  bool             `yaml:"tls_enabled,omitempty"`
	TLSCertFile string           `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile  string           `yaml:"tls_key_file,omitempty"`
	DNSServers  []string         `yaml:"dns_servers"`
	MaxConn     int              `yaml:"max_connections,omitempty"`
	Timeout     int              `yaml:"timeout,omitempty"`
}

type ListenerConfig struct {
	IP   string `yaml:"ip"`
	Port string `yaml:"port"`
}

type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ProxyServer struct {
	config     Config
	userMap    map[string]string
	authMutex  sync.RWMutex
	tlsConfig  *tls.Config
	resolver   *net.Resolver
	semaphore  chan struct{}
	httpClient *http.Client
}

func NewProxyServer(configPath string) (*ProxyServer, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("GaleProxy: configuration file not found at: %s", configPath)
	}

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("GaleProxy: failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		return nil, fmt.Errorf("GaleProxy: failed to parse YAML config: %v - check syntax", err)
	}

	if len(config.Listeners) == 0 {
		return nil, fmt.Errorf("GaleProxy: no listeners defined in config")
	}
	if len(config.Users) == 0 {
		return nil, fmt.Errorf("GaleProxy: no users defined in config")
	}
	if len(config.DNSServers) == 0 {
		return nil, fmt.Errorf("GaleProxy: no DNS servers specified in config")
	}

	if config.MaxConn <= 0 {
		config.MaxConn = 1000
	}
	if config.Timeout <= 0 {
		config.Timeout = 30
	}

	var tlsConfig *tls.Config
	if config.TLSEnabled {
		if config.TLSCertFile == "" || config.TLSKeyFile == "" {
			return nil, fmt.Errorf("GaleProxy: TLS enabled but cert_file or key_file not specified")
		}
		cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("GaleProxy: failed to load TLS certificates: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			MinVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
			InsecureSkipVerify: false,
		}
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(config.Timeout) * time.Second,
			}
			return d.DialContext(ctx, network, config.DNSServers[0])
		},
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		DialContext:         (&net.Dialer{Resolver: resolver, Timeout: time.Duration(config.Timeout) * time.Second}).DialContext,
		MaxIdleConns:        config.MaxConn,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	userMap := make(map[string]string)
	for _, user := range config.Users {
		if user.Username == "" || user.Password == "" {
			return nil, fmt.Errorf("GaleProxy: invalid user configuration: username or password empty")
		}
		userMap[user.Username] = user.Password
	}

	return &ProxyServer{
		config:    config,
		userMap:   userMap,
		tlsConfig: tlsConfig,
		resolver:  resolver,
		semaphore: make(chan struct{}, config.MaxConn),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(config.Timeout) * time.Second,
		},
	}, nil
}

func (ps *ProxyServer) authenticate(username, password string) bool {
	ps.authMutex.RLock()
	defer ps.authMutex.RUnlock()
	hashedPw, exists := ps.userMap[username]
	if !exists {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hashedPw), []byte(password)) == nil
}

func (ps *ProxyServer) handleConnection(w http.ResponseWriter, r *http.Request) {
	select {
	case ps.semaphore <- struct{}{}:
		defer func() { <-ps.semaphore }()
	default:
		http.Error(w, "GaleProxy: Too many connections", http.StatusServiceUnavailable)
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok || !ps.authenticate(username, password) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="GaleProxy"`)
		http.Error(w, "GaleProxy: Unauthorized", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		ps.handleHTTPS(w, r)
	} else {
		ps.handleHTTP(w, r)
	}
}

func (ps *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Real-IP")

	resp, err := ps.httpClient.Do(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("GaleProxy: Server Error: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (ps *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "GaleProxy: Invalid host", http.StatusBadRequest)
		return
	}

	var destConn net.Conn
	ctx := context.Background()
	addrs, err := ps.resolver.LookupHost(ctx, host)
	if err != nil {
		http.Error(w, fmt.Sprintf("GaleProxy: DNS resolution failed: %v", err), http.StatusServiceUnavailable)
		return
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		network := "tcp4"
		if ip.To4() == nil {
			network = "tcp6"
		}

		destConn, err = net.DialTimeout(network, r.Host, time.Duration(ps.config.Timeout)*time.Second)
		if err == nil {
			break
		}
	}

	if destConn == nil {
		http.Error(w, "GaleProxy: Failed to connect to destination", http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	if ps.config.TLSEnabled {
		destConn = tls.Client(destConn, ps.tlsConfig)
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "GaleProxy: Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("GaleProxy: Hijacking failed: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

func (ps *ProxyServer) Start() error {
	var wg sync.WaitGroup

	for i, listener := range ps.config.Listeners {
		wg.Add(1)
		addr := fmt.Sprintf("%s:%s", listener.IP, listener.Port)

		go func(addr string, idx int) {
			defer wg.Done()

			server := &http.Server{
				Addr:    addr,
				Handler: http.HandlerFunc(ps.handleConnection),
			}

			log.Printf("GaleProxy: Starting proxy server %d on %s (TLS: %v)", idx, addr, ps.config.TLSEnabled)
			var err error
			if ps.config.TLSEnabled {
				server.TLSConfig = ps.tlsConfig
				err = server.ListenAndServeTLS("", "")
			} else {
				err = server.ListenAndServe()
			}
			if err != nil && err != http.ErrServerClosed {
				log.Printf("GaleProxy: Error starting server %d on %s: %v", idx, addr, err)
			}
		}(addr, i)
	}

	wg.Wait()
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "GaleProxy: Error: Please provide config file path\nUsage: %s <config-file>\n", os.Args[0])
		os.Exit(1)
	}

	proxy, err := NewProxyServer(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "GaleProxy: Error: %v\n", err)
		os.Exit(1)
	}

	if err := proxy.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "GaleProxy: Error: Proxy server failed: %v\n", err)
		os.Exit(1)
	}
}
