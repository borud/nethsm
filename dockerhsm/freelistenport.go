package dockerhsm

import "net"

// freeListenPort returns a free port that we can use for listening.
func freeListenPort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
