package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/joho/godotenv"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func sshServerEstablishConnection() (*ssh.Client, error) {
	// Set up SSH config for the new Client

	// hostKeyCallback, err := knownhosts.New("/home/ncarob/.ssh/known_hosts")
	// if err != nil {
	// 	log.Printf("Error. Could not set up known_hosts: %v\n", err)
	// 	return nil, err
	// }
	config := &ssh.ClientConfig{
		User:            os.Getenv("SSH_USER"),
		Auth:            []ssh.AuthMethod{ssh.Password(os.Getenv("SSH_PASS"))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Establish an SSH Client connection to the Server
	conn, err := ssh.Dial(
		"tcp",
		os.Getenv("SSH_HOST")+":"+os.Getenv("SSH_PORT"),
		config,
	)
	if err != nil {
		log.Printf("Error. Could not establish SSH connection: %v\n", err)
		return nil, err
	}
	return conn, nil
}

func updateFile(client *sftp.Client, local string, remote string) error {
	fd, err := os.OpenFile(local, os.O_RDONLY, 0444)
	if err != nil {
		log.Printf("Error. Could not open a local file: %v\n", err)
		return err
	}
	defer fd.Close()

	data, err := io.ReadAll(fd)
	if err != nil {
		log.Printf("Error. Could not read the local file: %v\n", err)
		return err
	}

	sfd, err := client.Create(remote)
	if err != nil {
		log.Printf("Error. Could not open a remote file: %v\n", err)
		return err
	}
	defer sfd.Close()

	_, err = sfd.Write(data)
	if err != nil {
		log.Printf("Error. Could not write to the remote file: %v\n", err)
		return err
	}
	return nil
}

// Updates timetables & import & export tarifs when called by the handle.
func updateShipmentData(w http.ResponseWriter, _ *http.Request) {
	// Execute pure golang merge2pdf
	fmt.Fprintln(w, "Merging import & export pdfs...")
	cmd := exec.Command(
		"./merge2pdf",
		os.Getenv("PATH_TO_STAVKI"),
		os.Getenv("PATH_TO_IMPORT"),
		os.Getenv("PATH_TO_EXPORT"),
	)
	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(w, "Error. Could not merge import&export pdf files: %v\n", err)
		log.Printf("Error. Could not merge import&export pdf files: %v\n", err)
		return
	}
	fmt.Fprintln(w, "Successfully merged the pdf files.")

	// Set up an SSH client for sftp
	conn, err := sshServerEstablishConnection()
	if err != nil {
		fmt.Fprintf(w, "Error. Could not establish an SSH connection: %v\n", err)
		return
	}
	defer conn.Close()

	// Create an SFTP Client over the established connection
	fmt.Fprintln(w, "Establishing an sftp connection...")
	client, err := sftp.NewClient(conn)
	if err != nil {
		fmt.Fprintf(w, "Error: Could not create an SFTP client: %v\n", err)
		log.Printf("Error: Could not create an SFTP client: %v\n", err)
		return
	}
	defer client.Close()
	fmt.Fprintln(w, "Succesfully connected to SFTP via SSH.")

	// Updating rasp.pdf and stavki.pdf
	fmt.Fprintln(w, "Updating pdf files...")
	err = updateFile(
		client,
		os.Getenv("PATH_TO_RASPISANIE_LOCAL"),
		os.Getenv("PATH_TO_RASPISANIE_REMOTE"),
	)
	if err != nil {
		fmt.Fprintf(w, "Error. Could not update rasp.pdf: %v\n", err)
		return
	}
	err = updateFile(
		client,
		os.Getenv("PATH_TO_STAVKI_LOCAL"),
		os.Getenv("PATH_TO_STAVKI_REMOTE"),
	)
	if err != nil {
		fmt.Fprintf(w, "Error. Could not update stavki.pdf: %v\n", err)
		return
	}
	fmt.Fprintln(w, "Successfully updated pdf files.")
	log.Println("Successfully updated pdf files.")
}

// Set up basic https authentification to restrict user access.
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, pass, ok := r.BasicAuth()
		if ok {
			nameH := sha256.Sum256([]byte(name))
			passH := sha256.Sum256([]byte(pass))
			sNameH := sha256.Sum256([]byte(os.Getenv("PANDA_NAME")))
			sPassH := sha256.Sum256([]byte(os.Getenv("PANDA_PASS")))

			usernameMatch := (subtle.ConstantTimeCompare(nameH[:], sNameH[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passH[:], sPassH[:]) == 1)

			if usernameMatch && passwordMatch {
				log.Println("Successful authentification.")
				next.ServeHTTP(w, r)
				return
			} else {
				log.Printf("Warning. Failed authentification: %v:%v\n", name, pass)
			}
		}
		log.Println("Warning. New authentification attempt")
		w.Header().Set(
			"WWW-Authenticate",
			`Basic realm="restricted", charset="UTF-8"`,
		)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// Set up handles for the https server and start listening on port 4444.
func handleRequests() {
	http.HandleFunc("/update", basicAuth(updateShipmentData))

	err := http.ListenAndServeTLS(
		":4444",
		os.Getenv("TLS_CERTIFICATE"),
		os.Getenv("TLS_PRIVATEKEY"),
		nil,
	)
	log.Fatalf("%v", err)
}

func main() {
	// Load environment variables with config data
	err := godotenv.Load("../config/.env")
	if err != nil {
		log.Printf("Error. Could not load environment variables: %V\n", err)
	}
	handleRequests()
}
