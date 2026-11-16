package decoy

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// Decoy contents are made up: host names under .internal, addresses from private and
// documentation ranges, random passwords. Each file carries the host's canary marker, a
// random string generated once per host, so a copy found elsewhere can be traced back.

const (
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	pwSet  = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%*+-_"
	alnum  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digits = "0123456789"
)

func randFrom(set string, n int) string {
	var b strings.Builder
	max := big.NewInt(int64(len(set)))
	for range n {
		i, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err) // crypto/rand never fails on supported platforms
		}
		b.WriteByte(set[i.Int64()])
	}
	return b.String()
}

func randInt(n int) int {
	i, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(i.Int64())
}

// newCanary returns a fresh canary marker: 20 random base32 characters.
func newCanary() string { return randFrom(upper, 20) }

func pw() string { return randFrom(pwSet, 12+randInt(6)) }

func pick(xs ...string) string { return xs[randInt(len(xs))] }

// content returns a decoy's text for its kind.
func content(kind, user, canary string) []byte {
	if user == "" || user == "root" {
		user = pick("admin", "backup", "svc_backup")
	}
	u := strings.ToLower(user)
	var s string
	switch kind {
	case kindSheet:
		s = "Site,Username,Password,Notes\r\n" +
			fmt.Sprintf("Router,admin,%s,192.168.1.1\r\n", pw()) +
			fmt.Sprintf("NAS,%s,%s,nas.home.internal\r\n", u, pw()) +
			fmt.Sprintf("Wi-Fi,HomeNet-5G,%s,\r\n", pw()) +
			fmt.Sprintf("Email,%s@mail.home.internal,%s,old\r\n", u, pw()) +
			fmt.Sprintf("VPN,%s,%s,vpn.home.internal\r\n", u, pw()) +
			fmt.Sprintf("Password manager,%s,%s,recovery key %s\r\n", u, pw(), canary)
	case kindCodes:
		var b strings.Builder
		b.WriteString("Backup codes\r\n\r\nKeep these somewhere safe. Each code can be used once.\r\n\r\n")
		for i := 1; i <= 10; i++ {
			fmt.Fprintf(&b, "%2d. %s %s\r\n", i, randFrom(digits, 4), randFrom(digits, 4))
		}
		fmt.Fprintf(&b, "\r\nAccount: %s\r\nRecovery ID: %s\r\n", u, canary)
		s = b.String()
	case kindCSV:
		s = "host,service,username,password\r\n" +
			fmt.Sprintf("backup01.corp.internal,smb,svc_backup,%s\r\n", pw()) +
			fmt.Sprintf("sql02.corp.internal,mssql,sa,%s\r\n", pw()) +
			fmt.Sprintf("10.20.0.15,ssh,root,%s\r\n", pw()) +
			fmt.Sprintf("vcenter.corp.internal,https,administrator@vsphere.local,%s\r\n", pw()) +
			fmt.Sprintf("offsite.corp.internal,sftp,%s,%s\r\n", "bk_"+u, canary)
	case kindText:
		s = "passwords - do not share\n\n" +
			fmt.Sprintf("router admin: %s\n", pw()) +
			fmt.Sprintf("nas (%s): %s\n", u, pw()) +
			fmt.Sprintf("wifi HomeNet-5G: %s\n", pw()) +
			fmt.Sprintf("old laptop: %s\n", pw()) +
			fmt.Sprintf("bank pin hint: %s\n", randFrom(digits, 2)+"..") +
			fmt.Sprintf("password manager recovery key: %s\n", canary)
	case kindAWS:
		s = "[default]\n" +
			fmt.Sprintf("aws_access_key_id = AKIA%s\n", randFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)) +
			fmt.Sprintf("aws_secret_access_key = %s\n", randFrom(alnum, 40)) +
			"region = eu-west-1\n\n[backup-prod]\n" +
			fmt.Sprintf("aws_access_key_id = AKIA%s\n", randFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)) +
			fmt.Sprintf("aws_secret_access_key = %s%s\n", canary, randFrom(alnum, 20)) +
			"region = eu-west-1\n"
	case kindSQL:
		s = "-- MySQL dump 10.13  Distrib 8.0.36\n--\n-- Host: db01.corp.internal    Database: app\n" +
			"-- ------------------------------------------------------\n\n" +
			fmt.Sprintf("CREATE USER 'app'@'%%' IDENTIFIED BY '%s';\n", pw()) +
			"GRANT ALL PRIVILEGES ON app.* TO 'app'@'%';\n" +
			fmt.Sprintf("CREATE USER 'backup'@'10.20.0.%%' IDENTIFIED BY '%s';\n", pw()) +
			"GRANT SELECT, LOCK TABLES, SHOW VIEW ON *.* TO 'backup'@'10.20.0.%';\n" +
			fmt.Sprintf("CREATE USER 'repl'@'10.20.0.16' IDENTIFIED BY '%s';\n", canary) +
			"GRANT REPLICATION SLAVE ON *.* TO 'repl'@'10.20.0.16';\nFLUSH PRIVILEGES;\n"
	default:
		s = fmt.Sprintf("password: %s\nrecovery: %s\n", pw(), canary)
	}
	return []byte(s)
}
