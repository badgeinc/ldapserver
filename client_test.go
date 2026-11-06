package ldapserver

import (
	"net"
	"sync"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	ldap "github.com/vjeantet/goldap/message"
)

// TestConcurrentRequestListAccess exercises concurrent read/write access to
// client.requestList through GetMessageByID, registerRequest, and
// unregisterRequest. Without proper mutex protection on GetMessageByID
// (issue #28), this test fails under the race detector (-race).
func TestConcurrentRequestListAccess(t *testing.T) {
	c := &client{
		requestList: make(map[int]*Message),
	}

	const numMessages = 50
	const numReaders = 5

	// Build messages with distinct IDs.
	messages := make([]*Message, numMessages)
	for i := range messages {
		lm := ldap.NewLDAPMessageWithProtocolOp(NewBindResponse(LDAPResultSuccess))
		lm.SetMessageID(i + 1)
		messages[i] = &Message{
			LDAPMessage: lm,
			Done:        make(chan bool, 2),
			Client:      c,
		}
	}

	var wg sync.WaitGroup

	// Writers: register then unregister each message.
	for _, m := range messages {
		wg.Add(1)
		go func(m *Message) {
			defer wg.Done()
			c.registerRequest(m)
			c.unregisterRequest(m)
		}(m)
	}

	// Readers: concurrently look up message IDs while writers are active.
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := 1; id <= numMessages; id++ {
				c.GetMessageByID(id)
			}
		}()
	}

	wg.Wait()
}

// TestShutdownListenerRace exercises the race between the shutdown-listener
// goroutine calling wg.Add(1) and close() calling wg.Wait() (issue #25).
// Before the fix, the shutdown-listener goroutine could call wg.Add(1) after
// or concurrently with wg.Wait(), violating the sync.WaitGroup contract.
// This test reliably fails under `go test -race` without the fix.
func TestShutdownListenerRace(t *testing.T) {
	Logger = DiscardingLogger

	for i := 0; i < 50; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := ln.Addr().String()

		server := NewServer()
		routes := NewRouteMux()
		routes.Bind(func(w ResponseWriter, m *Message) {
			res := NewBindResponse(LDAPResultSuccess)
			w.Write(res)
		})
		server.Handle(routes)
		server.Listener = ln

		serveDone := make(chan error, 1)
		go func() {
			serveDone <- server.serve()
		}()

		// Establish a connection and complete a Bind so the client
		// goroutine is fully running with its shutdown-listener active.
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("iter %d: dial: %v", i, err)
		}
		if _, err := conn.Write(rawBindRequest); err != nil {
			conn.Close()
			t.Fatalf("iter %d: write bind: %v", i, err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			t.Fatalf("iter %d: read bind response: %v", i, err)
		}

		// Stop the server immediately — this closes chDone, triggering
		// the shutdown-listener goroutine while close() calls wg.Wait().
		server.Stop()
		conn.Close()

		select {
		case <-serveDone:
		case <-time.After(3 * time.Second):
			t.Fatalf("iter %d: serve() did not return after Stop()", i)
		}
	}
}

const testWriteTimeout = 100 * time.Millisecond

// startWriteTimeoutTestServer serves routes with testWriteTimeout set and returns its address.
func startWriteTimeoutTestServer(t *testing.T, routes *RouteMux) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := NewServer()
	server.ReadTimeout = 5 * time.Second
	server.WriteTimeout = testWriteTimeout
	server.Handle(routes)
	server.Listener = ln
	go server.serve()
	t.Cleanup(server.Stop)
	return ln.Addr().String()
}

// bindExpectingResponse sends rawBindRequest on conn and fails unless a BindResponse comes back.
func bindExpectingResponse(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write(rawBindRequest); err != nil {
		t.Fatalf("write bind request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp, err := decodeMessage(buf[:n])
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ProtocolOpName() != "BindResponse" {
		t.Fatalf("expected BindResponse, got %s", resp.ProtocolOpName())
	}
}

// TestWriteTimeoutAfterIdle checks that a bind after an idle longer than WriteTimeout gets its response while its handler is still running.
func TestWriteTimeoutAfterIdle(t *testing.T) {
	routes := NewRouteMux()
	routes.Bind(func(w ResponseWriter, m *Message) {
		w.Write(NewBindResponse(LDAPResultSuccess))
		time.Sleep(testWriteTimeout / 2)
	})
	addr := startWriteTimeoutTestServer(t, routes)

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	bindExpectingResponse(t, conn)
	time.Sleep(3 * testWriteTimeout)
	bindExpectingResponse(t, conn)
}

// TestWriteTimeoutSlowSearch checks that a search response written more than WriteTimeout after its request still reaches the client.
func TestWriteTimeoutSlowSearch(t *testing.T) {
	routes := NewRouteMux()
	routes.Search(func(w ResponseWriter, m *Message) {
		time.Sleep(3 * testWriteTimeout)
		w.Write(NewSearchResultDoneResponse(LDAPResultSuccess))
	})
	addr := startWriteTimeoutTestServer(t, routes)

	conn, err := goldap.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetTimeout(2 * time.Second)

	req := goldap.NewSearchRequest("dc=example", goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)
	if _, err := conn.Search(req); err != nil {
		t.Fatalf("search: %v", err)
	}
}
