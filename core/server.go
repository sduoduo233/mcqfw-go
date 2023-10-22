package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
)

const (
	VER                         = 0x05
	CMD_CONNECT                 = 0x01
	REP_SUCCESSED               = 0x00
	REP_CMD_NOT_SUPPORTED       = 0x07
	REP_ADDR_TYPE_NOT_SUPPORTED = 0x08
	ADDRESS_TYPE_v4             = 0x01
	ADDRESS_TYPE_DOMAIN         = 0x03
)

type Config struct {
	Listen      string
	Keywords    []string
	NFQueue     int
	WindowSize  uint16
	PacketCount int
	BytesCount  int64
}

var config Config
var dialer net.Dialer

func StartServer(c Config) error {
	config = c

	// go func() {
	// 	err := runNFQueue()
	// 	if err != nil {
	// 		log.Fatalf("nfqueue error: %s", err)
	// 	}
	// }()

	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return fmt.Errorf("listen error: %s", err)
	}

	log.Printf("listening at %s", config.Listen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept error: %s", err)
		}
		go func() {
			err = handleConn(conn)
			if err != nil {
				log.Printf("error: %s", err)
			}
		}()
	}

}

// handle socks5 connection
func handleConn(conn net.Conn) error {
	log.Printf("new connection: %s", conn.RemoteAddr().String())

	defer conn.Close()

	err := socks5Auth(conn)
	if err != nil {
		return err
	}

	dst, err := socks5Connect(conn)
	if err != nil {
		return err
	}

	// connect to destination
	dstConn, err := dialer.Dial("tcp", *dst)
	if err != nil {
		return err
	}
	dstConn.(*net.TCPConn).SetNoDelay(true)

	// set max window size
	_, portstr, _ := net.SplitHostPort(dstConn.LocalAddr().String())
	port, _ := strconv.Atoi(portstr)
	_, dstPort, _ := net.SplitHostPort(*dst)
	if dstPort == "443" {
		windowSizes[port] = config.WindowSize
	}

	// set defualt window size when connection ends
	defer func(p int) {
		windowSizes[p] = 0
		log.Printf("reset end %d", port)
	}(port)

	defer log.Printf("connection ends %s -> %s", conn.RemoteAddr().String(), *dst)

	// forward connection
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		// reset window size after copying n bytes
		io.CopyN(conn, dstConn, config.BytesCount)
		windowSizes[port] = 0
		log.Printf("reset bytes %d", port)

		io.Copy(conn, dstConn)
		conn.Close()
		wg.Done()
	}()
	go func() {
		forward(dstConn, conn, port)
		dstConn.Close()
		wg.Done()
	}()

	wg.Wait()

	return nil
}

// handle socks5 auth
func socks5Auth(conn net.Conn) error {
	buf := make([]byte, 256)

	// handshake
	_, err := io.ReadFull(conn, buf[0:2])
	if err != nil {
		return fmt.Errorf("read header error: %s", err)
	}

	ver := buf[0]
	if ver != 5 {
		return fmt.Errorf("wrong version: %d", ver)
	}

	nmethods := int(buf[1])
	_, err = io.ReadFull(conn, buf[:nmethods])
	if err != nil {
		return fmt.Errorf("read methods error: %s", err)
	}

	// no authentication
	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		return fmt.Errorf("write methods error: %s", err)
	}

	return nil
}

// send socks5 reply
func socks5Reply(conn net.Conn, reply byte) error {
	_, err := conn.Write([]byte{
		0x05,  // VER
		reply, // REP
		0x00,  // RSV
		0x01,  // ATYP
		0x00,  // BND.ADDR
		0x00,
		0x00,
		0x00,
		0x00, // BND.PORT
		0x00,
	})
	return err
}

// handle socks5 connect request
func socks5Connect(conn net.Conn) (*string, error) {
	buf := make([]byte, 256)

	_, err := io.ReadFull(conn, buf[:4])
	if err != nil {
		return nil, fmt.Errorf("read request error: %s", err)
	}

	cmd := buf[1]
	address_type := buf[3]
	if cmd != CMD_CONNECT {
		err = socks5Reply(conn, REP_CMD_NOT_SUPPORTED)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("socks5 connect: command %d not supported", cmd)
	}

	var addr string

	switch address_type {
	case ADDRESS_TYPE_v4:
		_, err := io.ReadFull(conn, buf[:4])
		if err != nil {
			return nil, fmt.Errorf("read ipv4 error: %s", err)
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

	case ADDRESS_TYPE_DOMAIN:
		_, err = io.ReadFull(conn, buf[:1])
		if err != nil {
			return nil, fmt.Errorf("read domain length error: %s", err)
		}
		n := int(buf[0])

		_, err = io.ReadFull(conn, buf[:n])
		if err != nil {
			return nil, fmt.Errorf("read domain error: %s", err)
		}
		addr = string(buf[:n])
	default:
		err = socks5Reply(conn, REP_ADDR_TYPE_NOT_SUPPORTED)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("socks5 connect: address type %d not supported", address_type)
	}

	_, err = io.ReadFull(conn, buf[:2])
	if err != nil {
		return nil, fmt.Errorf("read port error: %s", err)
	}
	port := binary.BigEndian.Uint16(buf[:2])
	addr = fmt.Sprintf("%s:%d", addr, port)

	log.Printf("connection %s -> %s", conn.RemoteAddr().String(), addr)

	return &addr, socks5Reply(conn, REP_SUCCESSED)
}
