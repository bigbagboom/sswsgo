package main

import (

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"	
	"fmt"

	"encoding/binary"
	"flag"

	"log"
	"net"
	"net/http"

	"net/url"
	"os"
	"os/signal"
	"strconv"
	"time"

	//"strings"

	"github.com/gorilla/websocket"
)

var addr string
var upgrader = websocket.Upgrader{} // use default options
var keystr string

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

func Mydecrypt(ciphertext []byte,keystr string) (decryptstr []byte) {

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

func sswsgo(w http.ResponseWriter, r *http.Request) {

	var conn net.Conn
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer c.Close()

	preaddrind := 0

	for {
		//mt, ciphertext, err := c.ReadMessage()
		_, ciphertext, err := c.ReadMessage()
		if err != nil {
			log.Println("read err 115:", err)
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
			log.Println("connect:",remotefull)

			conn, err = net.Dial("tcp", remotefull)
			if err != nil {
				// handle error
				log.Println("remote unreachable:", err)
				return
			}

			done := make(chan struct{})

			go func() {
				defer close(done)
				for {

					data := make([]byte, 4096)
					read_len, err := conn.Read(data)
					if read_len == 0 {
						continue
					}

					//log.Println("read from remote and write to ws: ", data)
					ciphertext = Myencrypt(data[:read_len], keystr)

					err = c.WriteMessage(websocket.BinaryMessage, ciphertext)
					if err != nil {
						log.Println("write err 172:", err)
						break
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
	log.Fatal(http.ListenAndServe(addr, nil))

}

func handleClient(conn net.Conn, urlstr string, port string, ch chan int) {

	conn.SetDeadline(time.Now().Add(10 * time.Minute))    // set 10 minutes timeout
	request := make([]byte, 262)                          
	defer conn.Close()                                    // close connection before exit

	addr := make([]byte, 0)
	conn.Read(request)
	conn.Write([]byte("\x05\x00"))
	data := make([]byte, 4)
	conn.Read(data)

	if len(data) == 4 && urlstr != "" {
		//fullurl := "http://" + urlstr + ":" + port + "/ws"
		fullurl := urlstr + ":" + port
		mode := data[1]
		addrtype := data[3]

		addrToSend := data[3:4]

		if addrtype == 1 {
			ip_bytes := make([]byte, 4)
			conn.Read(ip_bytes)

			//addr = socket.inet_ntoa(ip_bytes)
			addr = []byte(string(ip_bytes[0]) + "." + string(ip_bytes[1]) + "." + string(ip_bytes[2]) + "." + string(ip_bytes[3]))
			for _, v := range ip_bytes {
				addrToSend = append(addrToSend, v)
			}

		}
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

		port := make([]byte, 2)
		conn.Read(port)
		addrToSend = append(addrToSend, port[0], port[1])

		reply := []byte("\x05\x00\x00\x01\x00\x00\x00\x00")

		//log.Println("mode", mode, "fullurl:", fullurl, "reply:", reply, "addr:", addr, string(addr))

		if mode != 1 {
			reply := []byte("\x05\x07\x00\x01")
			conn.Write(reply)
			return
		}
		if mode == 1 {
			conn.Write(reply)
			conn.Write(port)

			interrupt := make(chan os.Signal, 1)
			signal.Notify(interrupt, os.Interrupt)

			u := url.URL{Scheme: "ws", Host: fullurl, Path: "ws"}

			c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
			if err != nil {
				log.Fatal("dial:", err)
			}
			defer c.Close()

			//log.Printf(" just before get chan")

			//lastcount := <-ch
			//ch <- lastcount + 1

			//log.Printf("%s connecting to %s", lastcount, u.String())

			ciphertext := Myencrypt(addrToSend, keystr)
			err = c.WriteMessage(websocket.BinaryMessage, ciphertext)

			if err != nil {
				log.Println("write:", err)
				return
			}

			done := make(chan struct{})

			go func() {
				defer close(done)
				for {
					_, ciphertext, err := c.ReadMessage()
					if err != nil {
						log.Println("read err 297:", err)
						return
					}
					plaintext := Mydecrypt(ciphertext, keystr)
					conn.Write(plaintext)
					//log.Printf("recv: %s", message)
				}
			}()

			for {
				data := make([]byte, 4096)
				read_len, err := conn.Read(data)
				if read_len == 0 {
					continue
				}
				ciphertext = Myencrypt(data[:read_len], keystr)

				err = c.WriteMessage(websocket.BinaryMessage, ciphertext)
				if err != nil {
					log.Println("write err 316:", err)
					return
				}

				data = make([]byte, 4096)

			}
		}

	}

}

func checkError(err error) {

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}

func myclient(hostname string, port string, urlstr string, sport string, ch chan int) {

	//ch <- 0

	service := hostname + ":" + port
	log.Println("This is a client(or local server) at " + service)

	tcpAddr, err := net.ResolveTCPAddr("tcp4", service)
	checkError(err)
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, urlstr, sport, ch)
	}
}

func main() {

	osenvkey := os.Getenv("SSWSGOPASS")


	s := flag.Bool("s", false, "Server")
	c := flag.Bool("c", false, "Client")
	hostname := flag.String("hostname", "127.0.0.1", "hostname")
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

	keystr = "passphrasewhichneedstobe32bytes!"   // default key, please do not use this!

	if osenvkey != "" {
		keystr = osenvkey
	}

	if *key != "" {
		keystr = *key
	}

	len_of_key := len(keystr)

	if len_of_key != 16  && len_of_key != 32 {
		log.Println("The length of keystr must be 16 or 32, exitting...")
		return
	}

	herokuport := os.Getenv("PORT")    //only for heroku

	sswsgoconcurrent := make(chan int)
	//sswsgoconcurrent <- 0

	if *s {
		//myserver(*sport)
		myserver(herokuport)     //only for heroku

	} else {
		
		myclient(*hostname, *port, *urlstr, *sport, sswsgoconcurrent)
	}

}
