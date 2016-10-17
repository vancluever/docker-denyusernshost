package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// activationMsg is a map[string]interface{} representation of the JSON
// message for what this plugin implements.
var activationMsg = map[string][]string{
	"Implements": []string{"authz"},
}

// socketPath is the path to the plugin socket.
const socketPath = "/run/docker/plugins/denyusernshost.sock"

var (
	// logBodyItems is a list of items to log from the immediate request body.
	// Fields are skipped if they are not defined.
	logBodyItems = []string{"Image", "Env", "Cmd", "Volumes"}

	// logHostConfigItems is a list of items to log from the HostConfig in the
	// request body. Fields are skipped if they are not defined.
	logHostConfigItems = []string{"VolumesFrom", "Binds"}
)

// authzReq is a struct representing an authorization request.
//
// /AuthZPlugin.AuthZReq is the authorize request method that is called before
// the Docker daemon processes the client request.
//
// This is also the struct used for /AuthZPlugin.AuthZRes as well, as we do
// not need to be concerned with any response data from Docker itself.
type authzReq struct {
	// The user identification.
	//
	// Note that this is populated only when TLS is enabled - when on, this
	// field will be populated by the common name of the client certificate.
	User string

	// The authentication method used.
	UserAuthNMethod string

	// The HTTP method.
	RequestMethod string

	// The HTTP request URI.
	RequestURI string

	// Byte array containing the raw HTTP request body.
	RequestBody []byte

	// Byte array containing the raw HTTP request headers as a map[string][]string.
	RequestHeader map[string][]string
}

// authResponse is a struct representing a Docker authz plugin API response.
//
// This response format is used for both /AuthZPlugin.AuthZReq and
// /AuthZPlugin.AuthZRes.
type authResponse struct {
	// Determines whether the user is allowed or not.
	Allow bool

	// The authorization message.
	Msg string

	// Msg for actual plugin errors.
	Err string
}

// listenUnix opens the plugin socket and starts listening.
//
// This will also try and create the parent directories that the socket needs
// to reside in (ie: /run/docker/plugins) if the path does not exist.
func listenUnix() net.Listener {
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		pluginDir := filepath.Dir(socketPath)
		log.Debugf("Creating %s for storing plugin socket", pluginDir)
		err = os.MkdirAll(pluginDir, 0750)
		if err != nil {
			errExit(1, "Creating %s failed: %v", pluginDir, err)
		}
	}
	os.Remove(socketPath)
	log.Infof("Listening on UNIX socket %s", socketPath)
	socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		errExit(1, "Error listening on %s: %v", socketPath, err)
	}
	return socket
}

// denyUsernsHost denys all requests and responses that have
// { "HostConfig": { "UsernsMode": "host" } } set in the request body.
//
// This is the main workhorse function of our plugin.
func denyUsernsHost(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req authzReq
	code := http.StatusBadRequest
	body := make([]byte, r.ContentLength)
	data := make(map[string]interface{})
	logData := make(map[string]interface{})
	resp := authResponse{
		Msg: "Request failed with error",
	}

	if r.ContentLength <= 0 {
		resp.Err = "Request has empty body"
		goto response
	}

	if n, err := io.ReadFull(r.Body, body); err != nil {
		log.Debugf("Error reading: read %d bytes of Content-Length of %d", n, r.ContentLength)
		resp.Err = fmt.Sprintf("Error reading request: %v", err)
		goto response
	}

	switch r.URL.Path {
	case "/AuthZPlugin.AuthZReq", "/AuthZPlugin.AuthZRes":
		if err := json.Unmarshal(body, &req); err != nil {
			resp.Err = fmt.Sprintf("Error parsing request JSON: %v", err)
			goto response
		}

		if len(req.RequestBody) > 0 {
			log.Debugf("Parsing original API request body: %s", req.RequestBody)
			if err := json.Unmarshal(req.RequestBody, &data); err != nil {
				resp.Err = fmt.Sprintf("Error reading original request JSON: %v", err)
				goto response
			}
		}
	default:
		resp.Err = fmt.Sprintf("%s not found on this server", r.URL.Path)
		goto response
	}

	for _, k := range logBodyItems {
		if v, ok := data[k]; ok && v != nil && v != reflect.Zero(reflect.TypeOf(v)) {
			logData[k] = v
		}
	}

	if v, ok := data["HostConfig"].(map[string]interface{}); ok {
		for _, k := range logHostConfigItems {
			if v, ok := v[k]; ok && v != nil && v != reflect.Zero(reflect.TypeOf(v)) {
				logData[k] = v
			}
		}
		if v, ok := v["UsernsMode"]; ok && v.(string) == "host" && strings.HasSuffix(req.RequestURI, "/containers/create") {
			// Apparently you don't send 403 for a successful deny.
			code = http.StatusOK
			resp.Msg = "userns=host is not allowed"
			goto response
		}
	}

	code = http.StatusOK
	resp.Allow = true
	resp.Msg = "Request allowed"

response:
	logDataStr, _ := json.Marshal(logData)
	log.Infof("%s %s - %d (Allowed: %t) - %s %s - %s", r.Method, r.URL.Path, code, resp.Allow, req.RequestMethod, req.RequestURI, logDataStr)

	respBody, _ := json.Marshal(resp)
	log.Debugf("Response JSON: %s", string(respBody))
	w.Header().Add("Content-Type", "application/json")
	http.Error(w, string(respBody), code)
}

func init() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()
	if debug {
		log.SetLevel(log.DebugLevel)
	}
}

func main() {
	log.Info("denyusernshost Docker authz plugin starting.")
	socket := listenUnix()
	http.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		respBody, _ := json.Marshal(activationMsg)
		log.Infof("%s %s - 200 - (Plugin activation request from docker daemon)", r.Method, r.URL.Path)
		io.WriteString(w, string(respBody))
	})
	http.HandleFunc("/AuthZPlugin.AuthZReq", denyUsernsHost)
	http.HandleFunc("/AuthZPlugin.AuthZRes", denyUsernsHost)
	log.Info("Press CTRL-C or send SIGTERM to close the server")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, unix.SIGTERM)
	go func() {
		s := <-c
		log.Infof("%s received, shutting down.", s.String())
		socket.Close()
		os.Remove(socketPath)
		os.Exit(0)
	}()
	log.Fatal(http.Serve(socket, nil))
}

// errExit exits with an error message, and the supplied code.
func errExit(code int, format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(code)
}
