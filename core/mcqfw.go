package core

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var windowSizes [65535]uint16

// iptables -A OUTPUT --source 192.168.31.243 -j NFQUEUE --queue-num 1
// iptables -A OUTPUT --source 192.168.31.86 ! -d 192.168.31.1/24 -j NFQUEUE --queue-num 1
// sysctl net.ipv4.tcp_window_scaling=0
func runNFQueue() error {

	config := nfqueue.Config{
		NfQueue:      1,
		MaxPacketLen: 0xFFFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	}

	// open nfqueue
	nf, err := nfqueue.Open(&config)
	if err != nil {
		return err
	}
	defer nf.Close()

	// NETLINK_NO_ENOBUFS
	rawConn, err := nf.Con.SyscallConn()
	if err != nil {
		return fmt.Errorf("SyscallConn error: %s", err)
	}

	err = rawConn.Control(func(fd uintptr) {
		SOL_NETLINK := 270
		NETLINK_NO_ENOBUFS := 5

		err := syscall.SetsockoptInt(int(fd), SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)
		if err != nil {
			log.Fatalf("SetsockoptInt error: %s", err)
		}
	})
	if err != nil {
		return fmt.Errorf("control error: %s", err)
	}

	ctx := context.Background()

	// callback
	callback := func(a nfqueue.Attribute) int {
		id := *a.PacketID

		packet := gopacket.NewPacket(*a.Payload, layers.LayerTypeIPv4, gopacket.Default)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// tcp packet
			tcp, _ := tcpLayer.(*layers.TCP)

			// modify window
			if windowSizes[tcp.SrcPort] != 0 && tcp.Window > windowSizes[tcp.SrcPort] {
				tcp.Window = windowSizes[tcp.SrcPort]
			}
			tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())

			// serialize packet
			buffer := gopacket.NewSerializeBuffer()

			err := gopacket.SerializePacket(buffer, gopacket.SerializeOptions{
				ComputeChecksums: true,
			}, packet)

			if err != nil {
				log.Printf("SerializePacket error: %s", err)
			}

			// modify packet
			nf.SetVerdictModPacket(id, nfqueue.NfAccept, buffer.Bytes())
		} else {
			// non-tcp packet
			nf.SetVerdict(id, nfqueue.NfAccept)
		}
		return 0
	}

	// register callback
	err = nf.RegisterWithErrorFunc(ctx, callback, func(e error) int {
		log.Fatalf("RegisterWithErrorFunc error: %s", e)
		return 0
	})
	if err != nil {
		return err
	}

	log.Printf("nfqueue started")

	<-ctx.Done()
	return nil
}

// forward srcConn to dstConn
func forward(dst net.Conn, src net.Conn, localPort int) error {
	packetCnt := 0
	buf := make([]byte, 10240)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return err
		}

		// http
		bufReplaced := bytes.ReplaceAll(buf[:n], []byte("Host:"), []byte("host:"))
		bufReplaced = bytes.ReplaceAll(bufReplaced, []byte("User-Agent:"), []byte("user-agent:"))

		packetCnt++

		// application data
		if bufReplaced[0] == 0x17 && windowSizes[localPort] != 0 {
			// set default window size if the client begins to send application data
			windowSizes[localPort] = 0
			log.Printf("reset app %d", localPort)
		}
		// packet count
		if packetCnt >= config.PacketCount && windowSizes[localPort] != 0 {
			windowSizes[localPort] = 0
			log.Printf("reset packet count %d", localPort)
		}

		// split
		offset := 0
		for _, keyword := range config.Keywords {
			idx := bytes.Index(bufReplaced, []byte(keyword))
			if idx != -1 {
				dst.Write(bufReplaced[offset : idx+1])
				offset = idx + 1
				break
			}
		}

		_, err = dst.Write(bufReplaced[offset:])
		if err != nil {
			return err
		}
	}
}
