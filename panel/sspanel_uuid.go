package panel

import (
	"crypto/md5"
	"fmt"
)

// SSPanelLegacyUUID reproduces U5ihx31fY.(*QhOI5ti).GetUser at 0x16ef3e0:
// gofrs/uuid.NewV3(uuid.NamespaceDNS, fmt.Sprintf("%d|%s", id, passwd)).
// MD5 here identifies historical accounts; it is not a password hash scheme.
func SSPanelLegacyUUID(id int64, password string) string {
	namespace := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := md5.New()
	h.Write(namespace)
	fmt.Fprintf(h, "%d|%s", id, password)
	u := h.Sum(nil)
	u[6] = (u[6] & 15) | 0x30
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[:4], u[4:6], u[6:8], u[8:10], u[10:])
}
