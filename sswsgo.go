package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"encoding/binary"
	"flag"
	"strings"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"time"
	"sync/atomic"
	"github.com/gorilla/websocket"
)

var addr string
var upgrader = websocket.Upgrader{} // use default options
var keystr string
var concurrent uint64

const (

	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Maximum message size allowed from peer.
	//maxMessageSize = 8192

	// Time allowed to read the next pong message from the peer.
	pongWait = 28 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
)

func Myencrypt(text []byte, keystr string) (ciphertext []byte) {

	key := []byte(keystr)

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		log.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		log.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	ciphertext = gcm.Seal(nonce, nonce, text, nil)
	return ciphertext

}

func Mydecrypt(ciphertext []byte, keystr string) (decryptstr []byte) {

	c, err := aes.NewCipher([]byte(keystr))
	if err != nil {
		log.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	decryptstr, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
	}

	return decryptstr
}

func nowstr() string {

	return time.Now().Format("2006-01-02 15:04:05.999")
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "tbbt")
}

func ping(ws *websocket.Conn, done chan struct{}) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
				log.Println("ping:", err)
			}
		case <-done:
			return
		}
	}
}

func sswsgo(w http.ResponseWriter, r *http.Request) {

	var conn net.Conn
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer c.Close()

	stdoutDone := make(chan struct{})
	go ping(c, stdoutDone)

	//c.SetReadLimit(maxMessageSize)
	c.SetReadDeadline(time.Now().Add(pongWait))
	c.SetPongHandler(func(string) error { c.SetReadDeadline(time.Now().Add(pongWait)); return nil })

	preaddrind := 0

	for {
		//mt, ciphertext, err := c.ReadMessage()
		_, ciphertext, err := c.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
				log.Printf("error: %v, user-agent: %v", err, r.Header.Get("User-Agent"))
				return
			} else {
				log.Println("read err 167:", err)
			}
			break
		}

		gotdata := Mydecrypt(ciphertext, keystr)
		var addrtype, addrlen byte
		remotehost := ""
		var remoteport int

		if preaddrind == 0 {
			preaddrind = 1

			addrtype = gotdata[0]

			if addrtype == 3 {
				addrlen = gotdata[1]
			}

			if addrtype == 1 {
				ip_bytes := make([]byte, 4)
				ip_bytes = gotdata[1:5]
				remotehost = string(ip_bytes[0]) + "." + string(ip_bytes[1]) + "." + string(ip_bytes[2]) + "." + string(ip_bytes[3])
				remoteport = int(binary.BigEndian.Uint16(gotdata[5:7]))
			}

			if addrtype == 3 {
				remotehost = string(gotdata[2 : 2+addrlen])
				remoteport = int(binary.BigEndian.Uint16(gotdata[2+addrlen : 4+addrlen]))
			}

			remotefull := remotehost + ":" + strconv.Itoa(remoteport)
			log.Println("connect: ", remotefull)

			conn, err = net.Dial("tcp", remotefull)
			if err != nil {
				// handle error
				log.Println("remote unreachable: ", err)
				return
			}
			conn.SetDeadline(time.Now().Add(10 * time.Minute)) // set 10 minutes timeout

			go func() {

				for {

					data := make([]byte, 4096)

					read_len, err := conn.Read(data)
					if err != nil {
					  if err != io.EOF {
					    log.Println("remote read err 212: ", err)
					  }
						break
					}
					
					if read_len > 0 {

					  ciphertext = Myencrypt(data[:read_len], keystr)
					  
					  err = c.WriteMessage(websocket.BinaryMessage, ciphertext)
					  if err != nil {
					    log.Println("write err 223: ", err)
					    break
					  }
					}
					data = make([]byte, 4096)
				}
			}()
		} else {

			if conn != nil {
				//log.Println("read from ws and write to remote: ", gotdata)
				conn.Write(gotdata)
			}
		}
	}
}

func myserver(port string) {

	//fmt.Println("this is a server")

	addr = ":" + port
	http.HandleFunc("/ws", sswsgo)
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(addr, nil))

}

func Proxy(proxystr string) func(*http.Request) (*url.URL, error) {

	myproxy := url.URL{Scheme: "http", Host: proxystr}

	return func(*http.Request) (*url.URL, error) {

		return &myproxy, nil

	}
}

func handleClient(conn net.Conn, urlstr string, sport string) {

	conn.SetDeadline(time.Now().Add(10 * time.Minute)) // set 10 minutes timeout
	defer conn.Close()                                 // close connection before exit

	addr := make([]byte, 0)
	request := make([]byte, 262)
	conn.Read(request)
	conn.Write([]byte("\x05\x00"))
	data := make([]byte, 4)
	conn.Read(data)

	if len(data) == 4 && urlstr != "" {

		mode := data[1]
		if mode != 1 {
			reply := []byte("\x05\x07\x00\x01")
			conn.Write(reply)
			return
		}

		addrtype := data[3]

		if addrtype != 1 && addrtype != 3 {

			log.Println(nowstr(), " unsupported addrtype: ", addrtype)
			return
		}

		addrToSend := data[3:4]

		if addrtype == 3 {
			addrlen_byte := make([]byte, 1)
			conn.Read(addrlen_byte)
			addrlen := addrlen_byte[0]
			addr = make([]byte, int(addrlen))
			conn.Read(addr)

			addrToSend = append(addrToSend, addrlen)

			for _, v := range addr {
				addrToSend = append(addrToSend, v)
			}
		}

		if addrtype == 1 {
			ip_bytes := make([]byte, 4)
			conn.Read(ip_bytes)

			//addr = socket.inet_ntoa(ip_bytes)
			addr = []byte(string(ip_bytes[0]) + "." + string(ip_bytes[1]) + "." + string(ip_bytes[2]) + "." + string(ip_bytes[3]))
			for _, v := range ip_bytes {
				addrToSend = append(addrToSend, v)
			}
		}

		fullurl := urlstr + ":" + sport

		port := make([]byte, 2)
		conn.Read(port)
		addrToSend = append(addrToSend, port[0], port[1])

		reply := []byte("\x05\x00\x00\x01\x00\x00\x00\x00")

		conn.Write(reply)
		conn.Write(port)

		atomic.AddUint64(&concurrent, 1)
		defer atomic.AddUint64(&concurrent, ^uint64(0))

		remotehost := ""

		if len(addrToSend)-2 > 2 {
			if addrtype == 3 {
				remotehost = string(addrToSend[2 : len(addrToSend)-2])
			} else {
				remotehost = string(addrToSend[1 : len(addrToSend)-2])
			}
		}

		if !strings.ContainsRune(remotehost, '.') {
			log.Println(nowstr(), " is the remotehost valid?")
			return
		}

		localclient := conn.RemoteAddr().String()
		idintotal := "[" + localclient + "] in total"

		log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "connect ->", remotehost, ":", int(binary.BigEndian.Uint16(port)))

		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)

		u := url.URL{Scheme: "ws", Host: fullurl, Path: "ws"}

		c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "dial:", err)
			return
		}
		defer c.Close()

		//c.SetReadLimit(maxMessageSize)
		c.SetReadDeadline(time.Now().Add(pingPeriod))
		c.SetPingHandler(func(string) error {
			if err := c.WriteControl(websocket.PongMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
				log.Println("pong:", err)
			}
			c.SetReadDeadline(time.Now().Add(pingPeriod))
			return nil
		})

		ciphertext := Myencrypt(addrToSend, keystr)
		err = c.WriteMessage(websocket.BinaryMessage, ciphertext)

		if err != nil {
			log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "write err 378:", err)
			return
		}

		go func() {

			for {

				_, ciphertext, err := c.ReadMessage()
				if err != nil {
					log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "websocket read err 388:", err)
					return
				}

				plaintext := Mydecrypt(ciphertext, keystr)
				if len(plaintext) != 0 {
					conn.Write(plaintext)
				}
			}
		}()

		for {

			data := make([]byte, 4096)
			
			read_len, err := conn.Read(data)
			
			if err != nil {
			  if err != io.EOF {
			    log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "local read err 407:", err)
			  }
			  break
			}
					
			if read_len > 0 {
			
			  ciphertext = Myencrypt(data[:read_len], keystr)
			  
			  err = c.WriteMessage(websocket.BinaryMessage, ciphertext)
			  if err != nil {
			    log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "websocket write err 418:", err)
			    return
			  }
			}
			data = make([]byte, 4096)
		}
	}
}

func checkError(err error) {

	if err != nil {
		log.Fatal("Fatal error: %s", err)
		os.Exit(1)
	}
}

func myclient(proxystr string, hostname string, port string, urlstr string, sport string) {

	//ch <- 0

	service := hostname + ":" + port
	log.Println("This is a client(or local server) at " + service)

	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	if proxystr != "" {
		websocket.DefaultDialer.Proxy = Proxy(proxystr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, urlstr, sport)
	}
}

func main() {

	osenvkey := os.Getenv("SSWSGOPASS")

	s := flag.Bool("s", false, "Server")
	c := flag.Bool("c", false, "Client")
	proxy := flag.String("proxy", "", "local http proxy")
	hostname := flag.String("hostname", "0.0.0.0", "hostname")
	port := flag.String("port", "7071", "port")
	sport := flag.String("sport", "80", "sport")
	urlstr := flag.String("urlstr", "", "sswsgo server url")
	key := flag.String("key", "", "16 bit or 32 bit passcode")

	flag.Parse()
	log.SetFlags(0)

	if *s && *c {
		log.Println("Please choose Server or Client，not both!")
		return
	}

	if (*s || *c) == false {
		log.Println("Please choose Server or Client，not none!")
		return
	}

	keystr = "passphrasewhichneedstobe32bytes!" // default key, please do not use this!

	if osenvkey != "" {
		keystr = osenvkey
	}

	if *key != "" {
		keystr = *key
	}

	len_of_key := len(keystr)

	if len_of_key != 16 && len_of_key != 32 {
		log.Println("The length of keystr must be 16 or 32, exitting...")
		return
	}

	herokuport := os.Getenv("PORT") //only for heroku

	if *s {
		//myserver(*sport)
		myserver(herokuport) //only for heroku

	} else {

		myclient(*proxy, *hostname, *port, *urlstr, *sport)
	}
}
