package identity
import ("sync"; "time")
type Mail struct { ID, From, To, Subject, Body string; Time time.Time }
type Mailbox struct { mu sync.Mutex; Messages []Mail }
func (m *Mailbox) SendMail(mail Mail) {}
func (m *Mailbox) ReceiveAll() []Mail { return nil }
type SMS struct { ID, From, To, Body string; Time time.Time }
type SMSBox struct { mu sync.Mutex; SMSs []SMS }
func (s *SMSBox) SendSMS(sms SMS) {}
func (s *SMSBox) ReceiveAll() []SMS { return nil }
