package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/theoffensivecoder/irestore/backup"
	"github.com/theoffensivecoder/irestore/pkg/irestore"
	"golang.org/x/crypto/ssh/terminal"
)

// Quick and Dirty error handling - when I don't expect an error, but want to know if it happens
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func getpass() string {
	fmt.Fprint(os.Stderr, "Backup Password: ")
	pw, err := terminal.ReadPassword(int(syscall.Stdin))
	must(err)
	fmt.Println()
	return string(pw)
}

func domains(db *backup.MobileBackup) {
	for _, domain := range irestore.Domains(db) {
		fmt.Println(domain)
	}
}

func apps(db *backup.MobileBackup) {
	for _, app := range irestore.Apps(db) {
		fmt.Println(app)
	}
}

func list(db *backup.MobileBackup, domain string) {
	for _, rec := range irestore.List(db, domain) {
		if domain == "*" {
			fmt.Println(rec.Domain, rec.Path)
		} else {
			fmt.Println(rec.Path)
		}
	}
}

func dumpkeys(db *backup.MobileBackup, outfile string) {
	data, err := irestore.DumpKeys(db, outfile)
	must(err)
	if outfile == "" {
		_, err = os.Stdout.Write(data)
		must(err)
	}
}

func encryptkeys(db *backup.MobileBackup, keys string, outfile string) {
	err := irestore.EncryptKeys(db, keys, outfile)
	must(err)
}

func restore(db *backup.MobileBackup, domain string, dest string, decryptedManifest []byte) {
	err := irestore.Restore(db, domain, dest, decryptedManifest)
	must(err)
	fmt.Println("Restore completed successfully")
}

func main() {
	help := func() {
		fmt.Println(`Usage:
    ls [domain]
    restore domain dest
    dumpkeys [outputfile]
    encryptkeys [inputfile] [outputfile]
    apps`)
	}

	var selected *backup.Backup

	if len(os.Args) > 1 {
		backupPath := os.Args[1]
		selected = &backup.Backup{DeviceName: "", FileName: backupPath}
	} else {
		help()
		return
	}

	db, err := backup.Open(selected.FileName)
	must(err)

	if db.Manifest.IsEncrypted {
		err = db.SetPassword(getpass())
		must(err)
	}

	decryptedManifest, err := db.Load()
	must(err)
	if len(os.Args) < 2 {
		for _, domain := range db.Domains() {
			fmt.Println(domain)
		}
		return
	}

	var cmd string
	if len(os.Args) > 2 {
		cmd = os.Args[2]
	}
	switch cmd {
	case "ls", "list":
		if len(os.Args) > 3 {
			list(db, os.Args[3])
		} else {
			domains(db)
		}
	case "restore":
		if len(os.Args) > 4 {
			restore(db, os.Args[3], os.Args[4], decryptedManifest)
		} else {
			help()
		}
	case "apps":
		apps(db)
	case "dumpkeys":
		var out string
		if len(os.Args) > 3 {
			out = os.Args[3]
		}
		dumpkeys(db, out)
	case "encryptkeys":
		if len(os.Args) > 4 {
			encryptkeys(db, os.Args[3], os.Args[4])
		}
	default:
		help()
	}
}
