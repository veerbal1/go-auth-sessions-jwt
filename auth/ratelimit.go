package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func NormalizeIP(ip string) string {
	return strings.TrimSpace(ip)
}

func hashKey(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func LoginEmailKey(email string) string {
	return "login:email:" + hashKey(NormalizeEmail(email))
}

func LoginIPKey(ip string) string {
	return "login:ip:" + hashKey(NormalizeIP(ip))
}

func LoginEmailIPKey(email, ip string) string {
	combined := NormalizeEmail(email) + ":" + NormalizeIP(ip)
	return "login:email_ip:" + hashKey(combined)
}
