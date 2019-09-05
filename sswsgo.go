package main

import (
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	//"encoding/hex"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	//"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DataQ struct {
	dq list.List
}

var remotehost string
var remoteport int
var keystr string
var concurrent uint64

const timeout = 10 * time.Minute
const errorend = "*** error or close ***"

var upgrader = websocket.Upgrader{} // use default options

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

	return time.Now().Format("2006-01-02 15:04:05.9999")
}

func handler(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(w, "tbbt")
}

func sswsgo(w http.ResponseWriter, r *http.Request) {

	var mu sync.Mutex
	var wg sync.WaitGroup

	var wqueue *DataQ
	wqueue = new(DataQ)

	var conn net.Conn
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer c.Close()

	connclient := "[" + c.UnderlyingConn().RemoteAddr().String() + "]"

	preaddrind := 0

	quit1 := make(chan struct{})
	quit2 := make(chan struct{})
	quit3 := make(chan struct{})
	quit4 := make(chan struct{})
	quit5 := make(chan struct{})
	quit6 := make(chan struct{})

	breakfor := false
	for {

		select {
		case <-quit1:
			breakfor = true
			break
		case <-quit4:
			breakfor = true
			break
		default:

			//mt, ciphertext, err := c.ReadMessage()
			_, ciphertext, err := c.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
					log.Printf(connclient, "error: ", err, ", user-agent: ", r.Header.Get("User-Agent"))
				} else {
					log.Println(connclient, "read err 164:", err)
				}

				mu.Lock()
				wqueue.dq.PushBack([]byte(errorend))
				mu.Unlock()

				breakfor = true
			} else {

				gotdata := Mydecrypt(ciphertext, keystr)

				var addrtype, addrlen byte

				if preaddrind == 0 {
					preaddrind = 1

					addrtype = gotdata[0]

					if addrtype == 3 {
						addrlen = gotdata[1]
					}

					if addrtype == 1 {
						ip_bytes := make([]byte, 4)
						ip_bytes = gotdata[1:5]
						remotehost = strconv.Itoa(int(ip_bytes[0])) + "." + strconv.Itoa(int(ip_bytes[1])) + "." + strconv.Itoa(int(ip_bytes[2])) + "." + strconv.Itoa(int(ip_bytes[3]))
						remoteport = int(binary.BigEndian.Uint16(gotdata[5:7]))
					}

					if addrtype == 3 {
						remotehost = string(gotdata[2 : 2+addrlen])
						remoteport = int(binary.BigEndian.Uint16(gotdata[2+addrlen : 4+addrlen]))
					}

					remotefull := remotehost + ":" + strconv.Itoa(remoteport)
					log.Println(connclient, "connect: ", remotefull)

					conn, err = net.Dial("tcp", remotefull)
					if err != nil {
						log.Println(connclient, "remote unreachable 202: ", err)
						breakfor = true
					} else {

						defer conn.Close()
						conn.SetDeadline(time.Now().Add(timeout)) // set 10 minutes timeout

						wg.Add(2)

						go func() {

							defer wg.Done()
							breakfor := false
							notwserr := true
							for {

								select {
								case <-quit2:
									breakfor = true
									break
								case <-quit5:
									breakfor = true
									break
								default:

									data := make([]byte, 4096)

									read_len, err := conn.Read(data)

									if err != nil {
										if err != io.EOF {
											log.Println(connclient, "remote read err 233: ", err)
											breakfor = true
										} else {
											if read_len == 0 {
												breakfor = true
											}
										}
									}

									if read_len > 0 {

										ciphertext = Myencrypt(data[:read_len], keystr)

										err = c.WriteMessage(websocket.BinaryMessage, ciphertext)
										if err != nil {
											log.Println(connclient, "websocket write err 248: ", err)
											notwserr = false
											breakfor = true
										}
									}
								}

								if breakfor {
									close(quit1)
									close(quit6)
									break
								}
							}

							if notwserr {

								ciphertext = Myencrypt([]byte(errorend), keystr)

								err = c.WriteMessage(websocket.BinaryMessage, ciphertext)
								if err != nil {
									log.Println(connclient, "websocket write err 268: ", err)
								}

							}
						}()

						go func() {

							defer wg.Done()
							breakfor := false
							for {
								select {
								case <-quit3:
									breakfor = true
									break
								case <-quit6:
									breakfor = true
									break
								default:

									if wqueue.dq.Len() > 0 {

										first := wqueue.dq.Front()
										dataforwrite := first.Value.([]byte)
										mu.Lock()
										wqueue.dq.Remove(first)
										mu.Unlock()

										if len(dataforwrite) == len([]byte(errorend)) && string(dataforwrite) == errorend {
											breakfor = true
										} else {
											conn.Write(dataforwrite)
											conn.SetDeadline(time.Now().Add(timeout)) // set 10 minutes timeout
										}

									} else {

										time.Sleep(time.Second)
									}
								}

								if breakfor {
									close(quit4)
									close(quit5)
									break
								}
							}

							for {
								if wqueue.dq.Len() > 0 {
									first := wqueue.dq.Front()
									dataforwrite := first.Value.([]byte)
									mu.Lock()
									wqueue.dq.Remove(first)
									mu.Unlock()

									if len(dataforwrite) == len([]byte(errorend)) && string(dataforwrite) == errorend {
										break
									} else {
										conn.Write(dataforwrite)
									}
								} else {
									break
								}
							}
						}()
					}
				} else {

					mu.Lock()
					wqueue.dq.PushBack(gotdata)
					mu.Unlock()
				}
			}
		}

		if breakfor {
			close(quit2)
			close(quit3)
			break
		}
	}

	wg.Wait()
}

func myserver(port string) {

	//log.Println("Server start")

	remoteaddr := ":" + port
	http.HandleFunc("/ws", sswsgo)
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(remoteaddr, nil))
}

func Proxy(proxystr string) func(*http.Request) (*url.URL, error) {

	myproxy := url.URL{Scheme: "http", Host: proxystr}

	return func(*http.Request) (*url.URL, error) {

		return &myproxy, nil
	}
}

func handleClient(conn net.Conn, urlstr string, sport string, tolog bool) {

	conn_need_closed := false
	localclient := conn.RemoteAddr().String()
	localclientid := "[" + localclient + "]"
	idintotal := localclientid + " in total"

	defer func() {
		conn.Close() // close connection before exit
		atomic.AddUint64(&concurrent, ^uint64(0))
		log.Println(nowstr(), localclientid, "closed. Concurrent connection is:", atomic.LoadUint64(&concurrent))
	}()

	conn.SetDeadline(time.Now().Add(timeout)) // set 10 minutes timeout

	var mu sync.Mutex
	var wg sync.WaitGroup

	var wqueue *DataQ
	wqueue = new(DataQ)

	var addr []byte

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

			log.Println(nowstr(), "unsupported addrtype: ", addrtype)
			return
		}

		addrToSend := data[3:]

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

			remotehost = string(addr)
		}

		ip_bytes := make([]byte, 4)

		if addrtype == 1 {

			conn.Read(ip_bytes)

			for _, v := range ip_bytes {
				addrToSend = append(addrToSend, v)
			}

			remotehost = strconv.Itoa(int(ip_bytes[0])) + "." + strconv.Itoa(int(ip_bytes[1])) + "." + strconv.Itoa(int(ip_bytes[2])) + "." + strconv.Itoa(int(ip_bytes[3]))
		}

		fullurl := urlstr + ":" + sport

		port := make([]byte, 2)
		conn.Read(port)
		addrToSend = append(addrToSend, port[0], port[1])

		conn.Write([]byte("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"))

		atomic.AddUint64(&concurrent, 1)

		remotefull := remotehost + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(port)))
		log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "connect ->", remotefull)

		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)

		u := url.URL{Scheme: "ws", Host: fullurl, Path: "ws"}

		c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {

			log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "dial:", err)
			return
		}
		defer c.Close()

		ciphertext := Myencrypt(addrToSend, keystr)
		err = c.WriteMessage(websocket.BinaryMessage, ciphertext)

		if err != nil {

			if tolog {
				log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "write err 485:", err)
			}
			return
		}

		quit1 := make(chan struct{})
		quit2 := make(chan struct{})
		quit3 := make(chan struct{})
		quit4 := make(chan struct{})

		wg.Add(3)

		go func() {

			defer wg.Done()
			breakfor := false
			for {

				select {
				case <-quit3:
					breakfor = true
					break
				default:
					if conn_need_closed {
						log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "conn need closed in websocket read goroutine but not! at 509")
					}

					_, ciphertext, err := c.ReadMessage()
					if err != nil {

						if tolog {
							log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "websocket read err 516:", err)
						}
						close(quit1)
						close(quit2)
						breakfor = true
						break
					}

					plaintext := Mydecrypt(ciphertext, keystr)

					if len(plaintext) != 0 {
						mu.Lock()
						wqueue.dq.PushBack(plaintext)
						mu.Unlock()
					}
				} // END OF SELECT

				if breakfor {
					break
				}
			}
		}()

		go func() {

			defer wg.Done()
			breakfor := false
			for {

				select {
				case <-quit1:
					breakfor = true
					break
				case <-quit4:
					breakfor = true
					break
				default:

					if conn_need_closed {
						log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "conn need closed in connection write goroutine but not! at 555")
					}

					if wqueue.dq.Len() > 0 {

						mu.Lock()

						first := wqueue.dq.Front()
						dataforwrite := first.Value.([]byte)

						conn.Write(dataforwrite)
						wqueue.dq.Remove(first)
						mu.Unlock()

					} else {

						time.Sleep(time.Second)
					}
				} //END OF SELECT

				if breakfor {
					break
				}
			}

			for {
				if wqueue.dq.Len() > 0 {

					mu.Lock()

					first := wqueue.dq.Front()
					dataforwrite := first.Value.([]byte)

					conn.Write(dataforwrite)
					wqueue.dq.Remove(first)
					mu.Unlock()

				} else {
					break
				}
			}
		}()

		go func() {

			defer wg.Done()
			breakfor := false
			for {

				data := make([]byte, 4096)

				select {
				case <-quit2:
					breakfor = true
					conn_need_closed = true
					break
				default:

					erreof := false
					read_len, err := conn.Read(data)

					if err != nil {
						if err != io.EOF {

							if tolog {
								log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "local read err 620:", err)
							}
							breakfor = true
							conn_need_closed = true
							break
						} else {

							erreof = true
							if read_len == 0 {

								if tolog {
									log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "local read length 0 at 631:", err)
								}
								breakfor = true
								conn_need_closed = true
								break
							}
						}
					}

					if read_len > 0 {

						ciphertext = Myencrypt(data[:read_len], keystr)

						err = c.WriteMessage(websocket.BinaryMessage, ciphertext)
						if err != nil {
							if tolog {
								log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "websocket write err 647:", err)
							}
							breakfor = true
							conn_need_closed = true
							break
						}
						if erreof {
							if tolog {
								log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "got io.EOF and local read length > 0. at 655")
							}
							breakfor = true
							conn_need_closed = true
							break
						}
					} else {
						if tolog {
							log.Println(nowstr(), idintotal, atomic.LoadUint64(&concurrent), "local read length 0 at 608 with no error. at 663")
						}
						breakfor = true
						conn_need_closed = true
						break
					}
				} // END OF SELECT

				if breakfor {
					close(quit3)
					close(quit4)
					break
				}
			}
		}()

		wg.Wait()
	}
}

func checkError(err error) {

	if err != nil {
		log.Fatal("Fatal error: %s", err)
		os.Exit(1)
	}
}

func myclient(proxystr string, hostname string, port string, urlstr string, sport string, tolog bool) {

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
		go handleClient(conn, urlstr, sport, tolog)
	}
}

func main() {

	osenvkey := os.Getenv("SSWSGOPASS")

	s := flag.Bool("s", false, "Server")
	c := flag.Bool("c", false, "Client")
	tolog := flag.Bool("tolog", false, "log or not")
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

		myclient(*proxy, *hostname, *port, *urlstr, *sport, *tolog)
	}
}
