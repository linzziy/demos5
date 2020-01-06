package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

const(
	RequestAccepted = iota
	SOCKSError
	ConnDeniedByRules
	NetUnreachable
	HostUnreachable
	ConnectionRefused
	TTLExpired
	CommandNotSupported
	AddrTypeNotSupported
)

type SocksServer struct {
	Version int
}

type Request struct {
	Version byte
	Command byte
	AddrType byte
	IP4Addr []byte
	IP6Addr []byte
	Host []byte
	Port int
}

type Response struct {
	Version byte
	ResponseCode byte
	AddrType byte
	AddrDest []byte
	Port []byte
}

func (s *SocksServer) write(resp *Response, conn net.Conn) error {

	b := []byte{resp.Version, resp.ResponseCode, 0, resp.AddrType}

	b = append(b, resp.AddrDest...)
	b = append(b, resp.Port...)

	log.Printf("buffer: %+v", resp)
	_, err := conn.Write(b)
	return err
}

func (s *SocksServer) error(conn net.Conn, respCode byte) error {
	resp := &Response{
		Version:      byte(s.Version),
		ResponseCode: respCode,
		AddrType:     0x1,
		AddrDest:     []byte{0, 0, 0, 0},
		Port:         []byte{0,0},
	}

	return s.write(resp, conn)
}

func (s *SocksServer) respond(conn net.Conn, ip net.IP, port int) error {

	var addr []byte
	var addrType int

	if ip.To4() != nil {
		addr = ip.To4()
		addrType = 0x1
	}else if ip.To16() != nil {
		addr = ip.To16()
		addrType = 0x4
	}else {
		return s.error(conn, AddrTypeNotSupported)
	}

	resp := &Response{
		Version:      byte(s.Version),
		ResponseCode: RequestAccepted,
		AddrType:     byte(addrType),
		AddrDest:     addr,
		Port:         []byte{byte(port >> 8), byte(port & 0xff)},
	}

	log.Printf("response: %+v", resp)
	return s.write(resp, conn)
}

func (s *SocksServer) proxy(dst io.Writer, src io.Reader, errCh chan error) error {
	_, err := io.Copy(dst, src)

	if closer, ok := dst.(*net.TCPConn); ok {
		closer.CloseWrite()
	}

	errCh <- err

	return nil
}

func (s *SocksServer) connect(conn net.Conn, req *Request) error {

	var addr string

	if req.Host != nil {
		ipAddr, err := net.ResolveIPAddr("ip", string(req.Host))
		if err != nil {
			return s.error(conn, SOCKSError)
		}
		addr = ipAddr.String()

	}else if req.IP4Addr != nil {
		addr = net.IPv4(
			req.IP4Addr[0],
			req.IP4Addr[1],
			req.IP4Addr[2],
			req.IP4Addr[3],
			).String()

	}else if req.IP6Addr != nil {
		addr = net.ParseIP(string(req.IP6Addr)).String()

	}else {
		return s.error(conn, AddrTypeNotSupported)
	}

	target, err := net.Dial("tcp", net.JoinHostPort(addr, strconv.Itoa(req.Port)))
	if err != nil {
		respCode := HostUnreachable
		if strings.Contains(err.Error(), "refused") {
			respCode = ConnectionRefused
		}else if strings.Contains(err.Error(), "network is unreachable") {
			respCode = NetUnreachable
		}

		return s.error(conn, byte(respCode))
	}

	defer target.Close()

	local := target.LocalAddr().(*net.TCPAddr)

	err = s.respond(conn, local.IP, local.Port)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)

	go s.proxy(target, conn, errCh)
	go s.proxy(conn, target, errCh)

	//<-errCh // 阻塞等待后台 goroutine 完成接收channel
	err = <- errCh
	if err != nil {
		return err
	}

	err = <- errCh
	if err != nil {
		return err
	}

	return nil
}

func (s *SocksServer) request(conn net.Conn, bConn *bufio.Reader) error {
	req := &Request{}

	header := make([]byte, 4)
	_, err := io.ReadAtLeast(bConn, header, 4)
	if err != nil {
		return err
	}

	req.Version = header[0]
	req.Command = header[1]
	req.AddrType = header[3]

	addrLen := 0

	switch req.AddrType {
	case 0x1:
		addrLen = 4
	case 0x4:
		addrLen = 16
	case 0x3:
		length, err := bConn.ReadByte()
		if err != nil {
			return err
		}
		addrLen = int(length)
	}

	portBytes := 2
	b := make([]byte, addrLen + portBytes)

	_, err = io.ReadFull(bConn, b)
	if err != nil {
		return err
	}

	switch req.AddrType {
	case 0x1:
		req.IP4Addr = b[:addrLen]
	case 0x4:
		req.IP6Addr = b[:addrLen]
	case 0x3:
		req.Host = b[:addrLen]
	}

	req.Port = int(int(b[addrLen]) << 8 | int(b[addrLen+1]))

	log.Printf("request: %+v, url:%s", req, req.Host)
	switch req.Command {
	case 0x1:
		return s.connect(conn, req)
	default:
		return s.error(conn, CommandNotSupported)
	}

	return nil
}

func (s *SocksServer) handleConnection(conn net.Conn) error {

	var err error
	bConn := bufio.NewReader(conn)
	version, err := bConn.ReadByte()
	if err != nil {
		return err
	}
	if int(version) != s.Version {
		return errors.New("version not supported")
	}

	authTypeCnt, err := bConn.ReadByte()

	authTypes := make([]byte, int(authTypeCnt))
	_, err = io.ReadFull(bConn, authTypes)
	if err != nil {
		return err
	}

	_, err = conn.Write([]byte{byte(s.Version), 0})
	if err != nil {
		return err
	}

	return s.request(conn, bConn)
}

func (s *SocksServer) ListenAndServer(protocol string, addr string) error {

	listen, err := net.Listen(protocol, addr)
	if err != nil {
		return err
	}
	log.Printf("listening: %s", addr)

	defer func() {
		log.Println("listener closed")
	}()

	for {
		conn, err := listen.Accept()
		if err != nil {
			return err
		}

		go func() {
			err = s.handleConnection(conn)
			if err != nil {
				log.Printf("connection error: %+v", err)
				return
			}
		}()
	}

	return nil
}

func main() {

	port := flag.Int("port", 7070, "port for proxy")
	flag.Parse()

	s := SocksServer{Version:5}

	err := s.ListenAndServer("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal(err)
	}
}
