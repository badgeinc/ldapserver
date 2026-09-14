package ldapserver

import (
	"bufio"
	"net"
	"sync"
	"time"

	ldap "github.com/vjeantet/goldap/message"
)

type client struct {
	Numero        int
	srv           *Server
	rwc           net.Conn
	br            *bufio.Reader
	bw            *bufio.Writer
	chanOut       chan writerJob
	wg            sync.WaitGroup
	closing       chan bool
	shutdownDone  chan struct{}
	requestList   map[int]*Message
	mutex         sync.Mutex
	writeDone     chan bool
	rawData       []byte
	data          any
	handler       Handler
	hasOwnHandler bool
}

func (c *client) GetConn() net.Conn {
	return c.rwc
}

func (c *client) GetRaw() []byte {
	return c.rawData
}

// GetData returns the custom data associated with this client connection.
func (c *client) GetData() any {
	return c.data
}

// SetData associates arbitrary custom data with this client connection.
// This can be used by handlers to store per-connection state such as
// authentication results or session information.
func (c *client) SetData(data any) {
	c.data = data
}

// SetConn swaps the connection's reader/writer, e.g. after a STARTTLS or a
// SASL security layer negotiates. The swap is applied on the same writer
// goroutine that flushes queued responses (see serve()'s writer goroutine
// and writerJob), and this call blocks until that actually happens -- so
// any response written via a ResponseWriter before this call is guaranteed
// to reach the wire on the old connection first, and the caller can safely
// read the next request through the new one as soon as this returns.
func (c *client) SetConn(conn net.Conn) {
	applied := make(chan struct{})
	c.chanOut <- writerJob{newConn: conn, applied: applied}
	<-applied
}

func (c *client) GetMessageByID(messageID int) (*Message, bool) {
	c.mutex.Lock()
	requestToAbandon, ok := c.requestList[messageID]
	c.mutex.Unlock()
	if ok {
		return requestToAbandon, true
	}
	return nil, false
}

func (c *client) Addr() net.Addr {
	return c.rwc.RemoteAddr()
}

func (c *client) ReadPacket() (*messagePacket, error) {
	mP, err := readMessagePacket(c.br)
	c.rawData = make([]byte, len(mP.bytes))
	copy(c.rawData, mP.bytes)
	return mP, err
}

func (c *client) callOnClose() {
	if c == nil || c.srv == nil || c.srv.OnClientClose == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			Logger.Printf("panic in OnClientClose for client [%d]: %v", c.Numero, r)
		}
	}()

	c.srv.OnClientClose(c.rwc, c.data)
}

func (c *client) serve() {
	defer c.close()

	c.closing = make(chan bool)
	c.shutdownDone = make(chan struct{})

	// Create the ldap response queue to be writted to client (buffered to 20)
	// buffered to 20 means that If client is slow to handler responses, Server
	// Handlers will stop to send more respones
	c.chanOut = make(chan writerJob)
	c.writeDone = make(chan bool)
	// For each job in c.chanOut, either write the message to the client or,
	// for a connection swap, apply it -- both on this one goroutine, so a
	// swap queued after a message is guaranteed to happen only once that
	// message has actually been flushed, and c.rwc/c.br/c.bw only ever have
	// one writer.
	go func() {
		for job := range c.chanOut {
			if job.newConn != nil {
				c.rwc = job.newConn
				c.br = bufio.NewReader(c.rwc)
				c.bw = bufio.NewWriter(c.rwc)
			} else {
				c.writeMessage(job.msg)
			}
			if job.applied != nil {
				close(job.applied)
			}
		}
		close(c.writeDone)
	}()

	// Listen for server signal to shutdown
	go func() {
		defer close(c.shutdownDone)
		for {
			select {
			case <-c.srv.chDone: // server signals shutdown process
				r := NewExtendedResponse(LDAPResultUnwillingToPerform)
				r.SetDiagnosticMessage("server is about to stop")
				r.SetResponseName(NoticeOfDisconnection)

				m := ldap.NewLDAPMessageWithProtocolOp(r)

				c.chanOut <- writerJob{msg: m}
				c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
				return
			case <-c.closing:
				return
			}
		}
	}()

	if onc := c.srv.OnNewConnection; onc != nil {
		if err := onc(c.rwc); err != nil {
			Logger.Printf("Erreur OnNewConnection: %s", err)
			return
		}
	}

	c.requestList = make(map[int]*Message)

	for {

		if c.srv.ReadTimeout != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(c.srv.ReadTimeout))
		}
		if c.srv.WriteTimeout != 0 {
			c.rwc.SetWriteDeadline(time.Now().Add(c.srv.WriteTimeout))
		}

		//Read client input as a ASN1/BER binary message
		messagePacket, err := c.ReadPacket()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				Logger.Printf("Sorry client %d, i can not wait anymore (reading timeout) ! %s", c.Numero, err)
			} else {
				Logger.Printf("Error readMessagePacket: %s", err)
			}
			return
		}

		//Convert ASN1 binaryMessage to a ldap Message
		message, err := messagePacket.readMessage()

		if err != nil {
			Logger.Printf("Error reading Message : %s\n\t%x", err.Error(), messagePacket.bytes)
			continue
		}
		Logger.Printf("<<< %d - %s - hex=%x", c.Numero, message.ProtocolOpName(), messagePacket)

		// TODO: Use a implementation to limit runnuning request by client
		// solution 1 : when the buffered output channel is full, send a busy
		// solution 2 : when 10 client requests (goroutines) are running, send a busy message
		// And when the limit is reached THEN send a BusyLdapMessage

		// When message is an UnbindRequest, stop serving
		if _, ok := message.ProtocolOp().(ldap.UnbindRequest); ok {
			return
		}

		// If client requests a startTls, do not handle it in a
		// goroutine, connection has to remain free until TLS is OK
		// @see RFC https://tools.ietf.org/html/rfc4511#section-4.14.1
		if req, ok := message.ProtocolOp().(ldap.ExtendedRequest); ok {
			if req.RequestName() == NoticeOfStartTLS {
				c.wg.Add(1)
				c.ProcessRequestMessage(&message)
				continue
			}
		}

		// Same reasoning for BindRequest: a handler completing a SASL
		// negotiation with a security layer swaps the connection's
		// reader/writer via SetConn, the same way StartTLS does. Handled
		// in a goroutine, this loop would already be blocked reading the
		// next message through the pre-swap reader by the time SetConn
		// runs, so the client's first protected message would be read as
		// plaintext and fail to parse. A client has no reason to pipeline
		// a request ahead of an outstanding bind completing anyway.
		if _, ok := message.ProtocolOp().(ldap.BindRequest); ok {
			c.wg.Add(1)
			c.ProcessRequestMessage(&message)
			continue
		}

		// TODO: go/non go routine choice should be done in the ProcessRequestMessage
		// not in the client.serve func
		c.wg.Add(1)
		go c.ProcessRequestMessage(&message)
	}

}

// close closes client,
// * stop reading from client
// * signals to all currently running request processor to stop
// * wait for all request processor to end
// * close client connection
// * signal to server that client shutdown is ok
func (c *client) close() {
	Logger.Printf("client %d close()", c.Numero)
	defer c.srv.wg.Done()

	close(c.closing)
	<-c.shutdownDone // wait for shutdown-listener goroutine to finish

	// stop reading from client
	c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
	Logger.Printf("client %d close() - stop reading from client", c.Numero)

	// signals to all currently running request processor to stop
	c.mutex.Lock()
	for messageID, request := range c.requestList {
		Logger.Printf("Client %d close() - sent abandon signal to request[messageID = %d]", c.Numero, messageID)
		go request.Abandon()
	}
	c.mutex.Unlock()
	Logger.Printf("client %d close() - Abandon signal sent to processors", c.Numero)

	c.wg.Wait()      // wait for all current running request processor to end
	close(c.chanOut) // No more message will be sent to client, close chanOUT
	Logger.Printf("client [%d] request processors ended", c.Numero)

	<-c.writeDone // Wait for the last message sent to be written
	c.callOnClose()
	c.rwc.Close() // close client connection
	Logger.Printf("client [%d] connection closed", c.Numero)
}

func (c *client) writeMessage(m *ldap.LDAPMessage) {
	data, _ := m.Write()
	Logger.Printf(">>> %d - %s - hex=%x", c.Numero, m.ProtocolOpName(), data.Bytes())
	c.bw.Write(data.Bytes())
	c.bw.Flush()
}

// writerJob is one item processed by serve()'s writer goroutine: either an
// LDAP message to write, or a connection swap (from SetConn) to apply once
// every previously queued message has been flushed. Routing both through
// the same channel guarantees that ordering, and keeps every mutation of
// c.rwc/c.br/c.bw on the one goroutine that also flushes to them. applied,
// when set, is closed once this job has been processed, so a caller (e.g.
// SetConn) can block until its effect is visible.
type writerJob struct {
	msg     *ldap.LDAPMessage
	newConn net.Conn
	applied chan struct{}
}

// ResponseWriter interface is used by an LDAP handler to
// construct an LDAP response.
type ResponseWriter interface {
	// Write writes the LDAPResponse to the connection as part of an LDAP reply.
	Write(po ldap.ProtocolOp)
}

type responseWriterImpl struct {
	chanOut   chan writerJob
	messageID int
}

func (w responseWriterImpl) Write(po ldap.ProtocolOp) {
	m := ldap.NewLDAPMessageWithProtocolOp(po)
	m.SetMessageID(w.messageID)
	w.chanOut <- writerJob{msg: m}
}

func (w responseWriterImpl) writeWithControls(po ldap.ProtocolOp, controls ldap.Controls) {
	m := ldap.NewLDAPMessageWithProtocolOp(po)
	m.SetMessageID(w.messageID)
	m.SetControls(controls.Pointer())
	w.chanOut <- writerJob{msg: m}
}

// controlsWriter is an optional interface for ResponseWriter implementations
// that support attaching controls to an LDAP response message.
type controlsWriter interface {
	writeWithControls(po ldap.ProtocolOp, controls ldap.Controls)
}

// WriteWithControls writes an LDAP response with the given controls attached
// to the LDAPMessage envelope. If the ResponseWriter does not support controls,
// it falls back to w.Write(po).
func WriteWithControls(w ResponseWriter, po ldap.ProtocolOp, controls ...ldap.Control) {
	if cw, ok := w.(controlsWriter); ok {
		cw.writeWithControls(po, ldap.Controls(controls))
		return
	}
	w.Write(po)
}

func (c *client) ProcessRequestMessage(message *ldap.LDAPMessage) {
	defer c.wg.Done()

	var m Message
	m = Message{
		LDAPMessage: message,
		Done:        make(chan bool, 2),
		Client:      c,
	}

	c.registerRequest(&m)
	defer c.unregisterRequest(&m)

	var w responseWriterImpl
	w.chanOut = c.chanOut
	w.messageID = m.MessageID().Int()

	if c.handler != nil {
		c.handler.ServeLDAP(w, &m)
	} else {
		c.srv.Handler.ServeLDAP(w, &m)
	}
}

func (c *client) registerRequest(m *Message) {
	c.mutex.Lock()
	c.requestList[m.MessageID().Int()] = m
	c.mutex.Unlock()
}

func (c *client) unregisterRequest(m *Message) {
	c.mutex.Lock()
	delete(c.requestList, m.MessageID().Int())
	c.mutex.Unlock()
}
