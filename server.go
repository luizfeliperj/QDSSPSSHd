// QDSSPSSHd: Quick dumb simple stupid passwordless ssh daemon meant for Singularity Containers
//
// Server:
// go build server.go
// singularity run image.sif server
//
// Client:
// ssh localhost -p 2200

package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

func main() {

	// In the latest version of crypto/ssh (after Go 1.3), the SSH server type has been removed
	// in favour of an SSH connection type. A ssh.ServerConn is created by passing an existing
	// net.Conn and a ssh.ServerConfig to ssh.NewServerConn, in effect, upgrading the net.Conn
	// into an ssh.ServerConn

	config := &ssh.ServerConfig{
		Config: ssh.Config{Ciphers: []string{
			"aes128-ctr",
			"aes192-ctr",
			"aes256-ctr",
		}},
		//Define a function to run when a client attempts a password login
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf("Authorized with password: %v/%v!!\n", c.User, string(pass))
			return &ssh.Permissions{Extensions: map[string]string{}}, nil
		},
		// You may also explicitly allow anonymous client authentication, though anon bash
		// sessions may not be a wise idea
		// NoClientAuth: true,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fingerprint := ssh.FingerprintSHA256(key)
			log.Printf("Authorized with public key: %v!!\n", fingerprint)
			return &ssh.Permissions{Extensions: map[string]string{}}, nil
		},
	}

	private, _ := getHostPrivateKey()
	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", ":2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	log.Print("Listening on 2200...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func getHostPrivateKey() (ssh.Signer, error) {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	_, privKey, _ := ed25519.GenerateKey(random)
	privSigner, _ := ssh.NewSignerFromKey(privKey)
	return privSigner, nil
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		var bashf *os.File
		for req := range requests {
			switch req.Type {
			case "exec":
				{
					cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
					command := string(req.Payload[4 : 4+cmdLen])
					req.Reply(true, nil)

					cmd := exec.Command("sh", "-c", command)
					stdin, err := cmd.StdinPipe()
					if err != nil {
						panic(err)
					}
					stdout, err := cmd.StdoutPipe()
					if err != nil {
						panic(err)
					}
					stderr, err := cmd.StderrPipe()
					if err != nil {
						panic(err)
					}

					go func() {
						io.Copy(stdin, connection)
					}()
					go func() {
						io.Copy(connection, stdout)
					}()
					go func() {
						io.Copy(connection, stderr)
					}()

					err = cmd.Run()

					exitCode := 1
					ret := make([]byte, 4)
					if exitError, ok := err.(*exec.ExitError); ok {
						exitCode = exitError.ExitCode()
						binary.BigEndian.PutUint32(ret, uint32(exitCode))
					}

					connection.SendRequest("exit-status", false, ret)
					connection.Close()
				}
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				} else {
					req.Reply(false, []byte{})
					continue
				}

				// Fire up bash for this session
				bash := exec.Command("bash")

				// Prepare teardown function
				close := func() {
					connection.Close()
					_, err := bash.Process.Wait()
					if err != nil {
						log.Printf("Failed to exit bash (%s)", err)
					}
					log.Printf("Session closed")
				}

				// Allocate a terminal for this channel
				log.Print("Creating pty...")
				bashf, err = pty.Start(bash)
				if err != nil {
					log.Printf("Could not start pty (%s)", err)
					close()
					return
				}

				//pipe session to bash and visa-versa
				var once sync.Once
				go func() {
					io.Copy(connection, bashf)
					once.Do(close)
				}()
				go func() {
					io.Copy(bashf, connection)
					once.Do(close)
				}()

			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)

			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)

			default:
				req.Reply(false, []byte{})
			}
		}
	}()
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

// Borrowed from https://github.com/creack/termios/blob/master/win/win.go
