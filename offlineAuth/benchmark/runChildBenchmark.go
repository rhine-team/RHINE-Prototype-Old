package main

import (
	//"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"path/filepath"
	"strconv"
	"strings"

	//"time"

	badger "github.com/dgraph-io/badger/v3"
	//"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	//"golang.org/x/exp/slices"
)

// This script should be run on the parent server

var zoneFixed = ".benchmark.ch"
var childkeyPrefix = "CHILDPK_"
var parentKeyPrefix = "PARENTSK_"
var parentCertPrefix = "PARENTCERT_"

func main() {
	fmt.Println("The following arguments needed: [ChildConfigPath (1)] [ChildKeyFileDir 2] [RequestRate 3]")
	// Path must end in a slash

	if len(os.Args) < 4 {
		log.Fatal("Need 3 arguments, not ", os.Args)
	}

	sleeptime, _ := strconv.Atoi(os.Args[3])

	if false {
		// Open  parent database (should be created if not existing yet)
		db, errdb := badger.Open(badger.DefaultOptions(os.Args[1]))
		if errdb != nil {
			log.Fatal("Badger error: ", errdb)
		}
		defer db.Close()

		child := []string{}
		err := db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchSize = 10
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				item := it.Item()
				k := item.Key()
				err := item.Value(func(v []byte) error {
					//fmt.Printf("key=%s, value=%s\n", k, v)
					ki := string(k)
					if strings.HasPrefix(ki, childkeyPrefix) {
						child = append(child, strings.TrimPrefix(ki, childkeyPrefix))
					}
					return nil
				})
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Fatalln("Error db: ", err)
		}
	}
	//log.Println("childs", child)
	log.Println("Db read")

	childKeyPath := []string{}
	childNames := []string{}

	filepath.Walk(os.Args[2], func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatalf(err.Error())
		}
		//fmt.Printf("File Name: %s\n", info.Name())
		if !strings.Contains(info.Name(), "_pub") && strings.Contains(info.Name(), ".pem") {
			zoneName := strings.Replace(info.Name(), ".pem", "", 1)
			childNames = append(childNames, zoneName)
			childKeyPath = append(childKeyPath, os.Args[2]+"/"+info.Name())
		}
		return nil
	})
	//log.Println("childnames", childNames)
	//log.Println("keypath", childKeyPath)

	for i, name := range childNames {
		cmdI := fmt.Sprint("../build/zoneManager RequestDeleg --config ", os.Args[1], " --output data/certs/delegResultCert.pem ", "--zone ", name, " --privkey ", childKeyPath[i], " &")
		cmd := exec.Command("bash", "-c", cmdI)
		//stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			log.Println(err)
		}
		log.Println("Started a client run")
		log.Println(cmdI)
		/*
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}
		*/
		time.Sleep(time.Duration(sleeptime) * time.Microsecond)

	}

	/*
		var err error
		parentName = GetParentZone(childName)
		// Get pcert
		pcerti, err = GetValueFromDB(zm.DB, []byte(parentCertPrefix+parentName))
		if err != nil {
			return nil, nil, nil, errors.New("Not a child zone of this parent!")
		}
		// Get parent key
		privatekeyparent, err = GetValueFromDB(zm.DB, []byte(parentKeyPrefix+parentName))
		if err != nil {
			return nil, nil, nil, errors.New("Not a child zone of this parent!")
		}
		// Get child key
		pKey, err = GetValueFromDB(zm.DB, []byte(childkeyPrefix+childName))
		if err != nil {
			return nil, nil, nil, errors.New("Not a child zone of this parent!")
		}
	*/

}
