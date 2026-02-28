package audit
import "log"
func LogAccess(service, secret string) { log.Printf("ACCESS: %s accessed %s", service, secret) }
