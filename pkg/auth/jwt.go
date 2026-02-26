package auth
func ValidateToken(t string) bool { return len(t) > 10 }
