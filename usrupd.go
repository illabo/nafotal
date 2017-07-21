package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/boltdb/bolt"
	"github.com/howeyc/gopass"
)

type User struct {
	Name    string
	Salt    []byte
	PassSha [32]byte
}

func main() {
	newuser := flag.String("adduser", "", "new user name")
	deluser := flag.String("delete", "", "user to delete")
	flag.Usage = func() {
		fmt.Printf("-adduser=username creates new user\n-delete=username removes user\nlist shows all usernames\n")
	}
	flag.Parse()
	if *newuser != "" {
		fmt.Println("Enter password for", *newuser)
		pass, err := gopass.GetPasswdMasked()
		if err != nil {
			log.Fatal(err)
		} else if len(pass) < 1 {
			fmt.Println("Password can't be blank.")
			return
		}

		fmt.Println("Re-nter password for", *newuser)
		pass_ver, err := gopass.GetPasswdMasked()
		if err != nil {
			log.Fatal(err)
		}

		if string(pass) == string(pass_ver) {
			salt := make([]byte, 8)

			_, err := io.ReadFull(rand.Reader, salt)
			if err != nil {
				log.Fatal(err)
			}

			var pass_sha256 [32]byte

			pass_sha256 = sha256.Sum256(append(pass, salt...))

			err = createUser(*newuser, pass_sha256, salt)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			err = errors.New("Passwords doesn't match.")
			fmt.Println(err)
		}

	}

	if *deluser != "" {
		err := deleteUser(*deluser)
		if err != nil {
			log.Fatal(err)
		}
	}

	if len(flag.Args()) > 0 && flag.Args()[0] == "list" {
		err := listUsers()
		if err != nil {
			log.Fatal(err)
		}
	}
}

func createUser(newuser string, pass_sha256 [32]byte, salt []byte) error {

	user_rec := User{
		Name:    newuser,
		Salt:    salt,
		PassSha: pass_sha256,
	}

	db, err := bolt.Open("db/data.db", 0644, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {

		ubucket, err := tx.CreateBucketIfNotExists([]byte("Users"))
		if err != nil {
			return err
		}

		value, err := json.Marshal(user_rec)
		if err != nil {
			return err
		}
		err = ubucket.Put([]byte(newuser), value)
		if err != nil {
			return err
		}

		return nil
	})

	fmt.Println("User \"" + newuser + "\" added to DB.")
	return err
}

func deleteUser(deluser string) error {
	db, err := bolt.Open("db/data.db", 0644, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("Users"))
		if bucket == nil {
			return nil
		}

		v := bucket.Get([]byte(deluser))
		if string(v) == "" {
			fmt.Println("No user \"" + deluser + "\" in DB.")
			return nil
		} else {
			err := bucket.Delete([]byte(deluser))
			if err == nil {
				fmt.Println("User \"" + deluser + "\" removed from DB.")
			}
			return err
		}
	})

	return err

}

func listUsers() error {
	db, err := bolt.Open("db/data.db", 0644, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("Users"))
		if b == nil {
			return nil
		}
		c := b.Cursor()

		fmt.Println("Users in DB:")
		i := 0

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if err != nil {
				return err
			}
			fmt.Println(string(k))
			i++
		}

		fmt.Println("Total users:", i)
		return nil
	})

	return err
}
