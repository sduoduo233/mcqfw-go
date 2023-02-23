package main

import (
	"flag"
	"log"
	"mcqfw/core"
	"strings"
)

var (
	listen      = flag.String("listen", "127.0.0.1:8081", "socks5 listen address")
	keywords    = flag.String("keywords", "taobao.com,.com,.cn,.net,.org", "keywords splited by \",\"")
	nfqueue     = flag.Int("nfqueue", 1, "nfqueue id")
	windowSize  = flag.Uint("window", 40, "window size")
	packetCount = flag.Int("packet", 5, "packet count")
	byteCount   = flag.Int64("byte", 512, "byte count")
)

func main() {
	flag.Parse()

	log.Println("mcqfw")

	err := core.StartServer(core.Config{
		Listen:      *listen,
		Keywords:    strings.Split(*keywords, ","),
		NFQueue:     *nfqueue,
		WindowSize:  uint16(*windowSize),
		PacketCount: *packetCount,
		BytesCount:  *byteCount,
	})
	if err != nil {
		log.Fatal("start error: ", err)
	}
}
