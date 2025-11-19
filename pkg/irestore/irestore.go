package irestore

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/dunhamsteve/plist"
	"github.com/theoffensivecoder/irestore/backup"
	"github.com/theoffensivecoder/irestore/crypto/aeswrap"
	"github.com/theoffensivecoder/irestore/crypto/gcm"
	"github.com/theoffensivecoder/irestore/encoding/asn1"
)

var le = binary.LittleEndian

// KCEntry represents a keychain entry
type KCEntry struct {
	Data []byte `plist:"v_Data"`
	Ref  []byte `plist:"v_PersistentRef"`
}

// Keychain represents the keychain structure
type Keychain struct {
	Internet []KCEntry `plist:"inet"`
	General  []KCEntry `plist:"genp"`
	Certs    []KCEntry `plist:"cert"`
	Keys     []KCEntry `plist:"keys"`
}

// Entry represents an ASN.1 entry
type Entry struct {
	Raw   asn1.RawContent
	Key   string
	Value interface{}
}

// DateEntry represents a date entry
type DateEntry struct {
	Key  string
	Time time.Time
}

// EntrySET is a set of entries
type EntrySET []Entry

// Domains returns all domains in the backup
func Domains(db *backup.MobileBackup) []string {
	return db.Domains()
}

// Apps returns all application identifiers in the backup
func Apps(db *backup.MobileBackup) []string {
	apps := make([]string, 0, len(db.Manifest.Applications))
	for app := range db.Manifest.Applications {
		apps = append(apps, app)
	}
	return apps
}

// RecordInfo contains information about a backup record
type RecordInfo struct {
	Domain string
	Path   string
}

// List returns all file records matching the given domain.
// If domain is "*", returns records from all domains.
func List(db *backup.MobileBackup, domain string) []RecordInfo {
	var records []RecordInfo
	for _, rec := range db.Records {
		// just files for now
		if rec.Length > 0 {
			if domain == "*" {
				records = append(records, RecordInfo{
					Domain: rec.Domain,
					Path:   rec.Path,
				})
			} else if domain == rec.Domain {
				records = append(records, RecordInfo{
					Domain: rec.Domain,
					Path:   rec.Path,
				})
			}
		}
	}
	return records
}

// Restore restores files from the backup to the destination directory.
// If domain is "*", restores all domains; otherwise restores only the specified domain.
func Restore(db *backup.MobileBackup, domain string, dest string, decryptedManifest []byte) error {
	err := os.MkdirAll(dest, 0755)
	if err != nil {
		return err
	}

	err = os.WriteFile(path.Join(dest, "Manifest.db"), decryptedManifest, 0644)
	if err != nil {
		return err
	}

	for _, rec := range db.Records {
		if rec.Length > 0 {
			var outPath string
			if domain == "*" {
				outPath = path.Join(dest, rec.Domain, rec.Path)
			} else if rec.Domain == domain {
				outPath = path.Join(dest, rec.Path)
			}

			if outPath != "" {
				dir := path.Dir(outPath)
				err = os.MkdirAll(dir, 0755)
				if err != nil {
					return err
				}
				r, err := db.FileReader(rec)
				if err != nil {
					return fmt.Errorf("error reading file %s: %w", rec.Path, err)
				}
				w, err := os.Create(outPath)
				if err != nil {
					r.Close()
					return err
				}
				_, err = io.Copy(w, r)
				r.Close()
				w.Close()
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func parseRecord(data []byte) map[string]interface{} {
	var v EntrySET
	rval := make(map[string]interface{})
	_, err := asn1.Unmarshal(data, &v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing record: %v\n", err)
		ioutil.WriteFile("failed.bin", data, 0644)
	}
	keys := make([]string, 0, len(v))
	types := make([]string, 0, len(v))
	for _, entry := range v {
		// Time values come through as nil, so we try again with a "DateEntry" structure.
		if entry.Value == nil {
			var entry2 DateEntry
			_, err := asn1.Unmarshal(entry.Raw, &entry2)
			if err == nil {
				entry.Value = entry2.Time
			}
		}

		rval[entry.Key] = entry.Value
		keys = append(keys, entry.Key)
		types = append(types, reflect.TypeOf(entry.Value).String())
	}

	rval["_fieldOrder"] = strings.Join(keys, ",")
	rval["_fieldTypes"] = strings.Join(types, ",")
	return rval
}

func dumpKeyGroup(db *backup.MobileBackup, group []KCEntry) []interface{} {
	var rval []interface{}
	for _, key := range group {
		version := le.Uint32(key.Data)
		class := le.Uint32(key.Data[4:])
		switch version {
		case 3:
			l := le.Uint32(key.Data[8:])
			wkey := key.Data[12 : 12+l]
			edata := key.Data[12+l:]

			// Find key for class
			ckey := db.Keybag.GetClassKey(class)
			if ckey == nil {
				fmt.Fprintf(os.Stderr, "No key for class %d (ref: %s%v)\n", class, string(key.Ref)[:4], key.Ref[4:])
				continue
			}

			aesKey := aeswrap.Unwrap(ckey, wkey)
			if aesKey == nil {
				fmt.Fprintf(os.Stderr, "unwrap failed for class %d\n", class)
				continue
			}
			// Create a gcm cipher
			c, err := aes.NewCipher(aesKey)
			if err != nil {
				panic(err)
			}
			gcm, err := gcm.NewGCM(c)
			if err != nil {
				panic(err)
			}
			plain, err := gcm.Open(nil, nil, edata, nil)
			if err != nil {
				panic(err)
			}

			record := parseRecord(plain)
			record["_class"] = class
			record["_version"] = version
			record["_wkey"] = wkey
			record["_length"] = l
			record["_ref"] = key.Ref

			rval = append(rval, record)
		default:
			panic(fmt.Sprintf("Unhandled keychain blob version %d", version))
		}
	}

	return rval
}

// DumpKeys extracts and decrypts keychain entries from the backup.
// If outfile is empty, returns the JSON data as bytes; otherwise writes to the file.
func DumpKeys(db *backup.MobileBackup, outfile string) ([]byte, error) {
	for _, rec := range db.Records {
		if rec.Domain == "KeychainDomain" && rec.Path == "keychain-backup.plist" {
			data, err := db.ReadFile(rec)
			if err != nil {
				return nil, err
			}

			var v Keychain
			err = plist.Unmarshal(bytes.NewReader(data), &v)
			if err != nil {
				return nil, err
			}

			dump := make(map[string][]interface{})
			dump["General"] = dumpKeyGroup(db, v.General)
			dump["Internet"] = dumpKeyGroup(db, v.Internet)
			dump["Certs"] = dumpKeyGroup(db, v.Certs)
			dump["Keys"] = dumpKeyGroup(db, v.Keys)
			s, err := json.MarshalIndent(dump, "", "  ")
			if err != nil {
				return nil, err
			}
			if outfile != "" {
				err = ioutil.WriteFile(outfile, s, 0644)
				if err != nil {
					return nil, err
				}
			}
			return s, nil
		}
	}
	return nil, fmt.Errorf("keychain-backup.plist not found")
}

func unparseRecord(record map[string]interface{}) []byte {
	var v EntrySET

	keys := strings.Split(fmt.Sprint(record["_fieldOrder"]), ",")
	types := strings.Split(fmt.Sprint(record["_fieldTypes"]), ",")

	for index, key := range keys {
		if strings.HasPrefix(key, "_") {
			continue
		}

		var entry Entry
		entry.Key = key

		switch types[index] {
		case "int64":
			entry.Value = int(record[key].(float64))
		case "string":
			entry.Value = record[key].(string)
		case "time.Time":
			const formatStr = "2006-01-02T15:04:05.999999999Z"
			t, _ := time.Parse(formatStr, record[key].(string))
			entry.Value = t
		default:
			value, _ := base64.StdEncoding.DecodeString(record[key].(string))
			entry.Value = value
		}

		v = append(v, entry)
	}

	entries, err := asn1.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling record: %v\n", err)
	}

	return entries
}

func encryptKeyGroup(db *backup.MobileBackup, group interface{}, class string) []KCEntry {
	var rval []KCEntry

	if group == nil {
		return rval
	}

	for _, record := range group.([]interface{}) {
		var entry KCEntry

		recordObject := record.(map[string]interface{})

		ckey := db.Keybag.GetClassKey(uint32(recordObject["_class"].(float64)))
		wkey, _ := base64.StdEncoding.DecodeString(recordObject["_wkey"].(string))
		key := aeswrap.Unwrap(ckey, wkey)

		c, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		gcm, err := gcm.NewGCM(c)
		if err != nil {
			panic(err)
		}

		unparsed := unparseRecord(recordObject)

		nonce := []byte{}
		ciphertext := gcm.Seal(nil, nonce, unparsed, nil)

		data := make([]byte, 12)
		le.PutUint32(data, uint32(recordObject["_version"].(float64)))
		le.PutUint32(data[4:], uint32(recordObject["_class"].(float64)))
		le.PutUint32(data[8:], uint32(recordObject["_length"].(float64)))
		data = append(data, wkey...)
		data = append(data, ciphertext...)

		entry.Data = data
		ref, _ := base64.StdEncoding.DecodeString(recordObject["_ref"].(string))
		entry.Ref = ref

		rval = append(rval, entry)
	}

	return rval
}

// EncryptKeys encrypts keychain entries from a JSON file and writes them to a plist file.
func EncryptKeys(db *backup.MobileBackup, keys string, outfile string) error {
	jsonFile, err := os.Open(keys)
	if err != nil {
		return err
	}
	defer jsonFile.Close()

	jsonBytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return err
	}
	jsonMap := make(map[string](interface{}))
	err = json.Unmarshal(jsonBytes, &jsonMap)
	if err != nil {
		return err
	}

	path := os.ExpandEnv(outfile)
	plistFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer plistFile.Close()

	emptyPlist := []byte{98, 112, 108, 105, 115, 116, 48, 48, 208, 8, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
	_, err = plistFile.Write(emptyPlist)
	if err != nil {
		return err
	}

	var v Keychain
	err = plist.Unmarshal(plistFile, v)
	if err != nil {
		return err
	}

	v.General = encryptKeyGroup(db, jsonMap["General"], "genp")
	v.Internet = encryptKeyGroup(db, jsonMap["Internet"], "inet")
	v.Certs = encryptKeyGroup(db, jsonMap["Certs"], "cert")
	v.Keys = encryptKeyGroup(db, jsonMap["Keys"], "keys")

	out, err := plist.Marshal(v)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, out, 0644)
	if err != nil {
		return err
	}

	return nil
}
