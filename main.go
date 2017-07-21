package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/acme/autocert"

	"github.com/boltdb/bolt"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"gopkg.in/h2non/bimg.v1"
)

var store *sessions.CookieStore

var saveErrchan chan error = make(chan error)

type PageBody struct {
	Name  string
	Files template.JS
}

type User struct {
	Name    string
	Salt    []byte
	PassSha [32]byte
}

func init() {
	cookkey := make([]byte, 8)

	_, err := io.ReadFull(rand.Reader, cookkey)
	if err != nil {
		log.Fatal(err)
	}
	store = sessions.NewCookieStore(cookkey)
}

func main() {

	go http.ListenAndServe(":80", context.ClearHandler(http.HandlerFunc(redirectToHTTPS)))

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))

	http.HandleFunc("/", mainpageHandler)

	http.HandleFunc("/upload", uploadsHandler)

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("someofmy.photos"), //your domain here
		Cache:      autocert.DirCache("certs"),                //folder for storing certificates
	}

	server := &http.Server{
		Addr: ":443",
		TLSConfig: &tls.Config{
			ServerName:     "someofmy.photos",
			GetCertificate: certManager.GetCertificate,
		},
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		print(err.Error())
	} //key and cert are comming from Let's Encrypt
}

func dedupe(list []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for v := range list {
		if encountered[list[v]] == true || strings.TrimSpace(list[v]) == "" {
		} else {
			encountered[list[v]] = true
			result = append(result, strings.Fields(list[v])...)
		}
	}
	return result
}

func storeFilesToDB(tags map[string][]string) error {
	db, err := bolt.Open("db/data.db", 0644, nil)
	if err != nil {
		return err
	}

	err = db.Update(func(tx *bolt.Tx) error {

		fbucket, err := tx.CreateBucketIfNotExists([]byte("Files"))
		if err != nil {
			return err
		}

		for k, v := range tags {
			valbytes, err := json.Marshal(v)
			if err != nil {
				return err
			}
			err = fbucket.Put([]byte(k), valbytes)
			if err != nil {
				return err
			}
		}

		return nil
	})
	db.Close()

	return err
}

func deleteFileFromDB(key string) error {
	db, err := bolt.Open("db/data.db", 0644, nil)
	if err != nil {
		return err
	}

	err = db.Update(func(tx *bolt.Tx) error {

		return tx.Bucket([]byte("Files")).Delete([]byte(key))

	})
	db.Close()

	return err
}

func getUserFromDB(key string) (User, error) {
	var userdata User

	db, err := bolt.Open("db/data.db", 0644, nil)
	if err != nil {
		return userdata, err
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("Users"))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(key))
		if string(v) == "" {
			return nil
		}

		err := json.Unmarshal(v, &userdata)
		if err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return userdata, err
	}

	db.Close()

	return userdata, err
}

func resizeAndSave(file *multipart.FileHeader, filename string, saveErrchan chan error) {
	options := bimg.Options{
		Width:        840,
		Quality:      95,
		Interpolator: bimg.Nohalo,
	}

	ofile, err := file.Open()
	defer ofile.Close()
	if err != nil {
		saveErrchan <- err
		return
	}

	imgfilebuff, err := ioutil.ReadAll(ofile)
	if err != nil {
		saveErrchan <- err
		return
	}

	img, err := bimg.NewImage(imgfilebuff).Process(options)
	if err != nil {
		saveErrchan <- err
		return
	}

	out := "assets/photos/" + filename

	// write new image to file
	err = bimg.Write(out, img)

	saveErrchan <- err
	return
}

func redirectToHTTPS(res http.ResponseWriter, req *http.Request) {
	// from https://gist.github.com/d-schmidt/587ceec34ce1334a5e60
	// remove/add not default ports from req.Host
	target := "https://" + req.Host + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}
	http.Redirect(res, req, target,
		// see @andreiavrammsd comment: often 307 > 301
		http.StatusTemporaryRedirect)
}

func mainpageHandler(res http.ResponseWriter, req *http.Request) {

	allfiles := make(map[string][]string)

	db, err := bolt.Open("db/data.db", 0644, nil)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		context.Clear(req)
		return
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("Files"))
		if b == nil {
			return nil
		}
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var filetags []string
			err := json.Unmarshal(v, &filetags)
			if err != nil {
				return err
			}
			allfiles[string(k)] = dedupe(filetags)
		}

		return nil
	})

	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		context.Clear(req)
		return
	}
	db.Close()

	var filesjson []byte
	filesjson, err = json.Marshal(allfiles)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		context.Clear(req)
		return
	}

	pbod := PageBody{
		Name:  "",
		Files: template.JS(filesjson),
	}
	var tmplt *template.Template

	session, _ := store.Get(req, "admin")
	// if err != nil {
	// 	http.Error(res, err.Error(), http.StatusInternalServerError)
	// 	context.Clear(req)
	// 	return
	// }

	var userstruct User

	if session.Values["name"] != nil {

		userstruct, err = getUserFromDB(session.Values["name"].(string))
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}

	}

	storedpass := fmt.Sprintf("%x", userstruct.PassSha)

	if session.Values["name"] == nil || session.Values["pwd"] == nil || session.Values["pwd"].(string) != storedpass {
		session.Values["name"] = ""
		session.Values["pwd"] = ""
	}

	switch session.Values["name"].(string) + session.Values["pwd"].(string) {
	case userstruct.Name + storedpass:

		if req.Method == "DELETE" {
			delete(session.Values, "name")

			session.Save(req, res)
			context.Clear(req)
			return

		} else if req.Method == "POST" {

			req.ParseForm()

			for key, value := range req.Form {
				switch key {
				case "uname":
					fallthrough
				case "pwd":
					context.Clear(req)
					http.Redirect(res, req, "/", http.StatusBadRequest)
				default:
					if value[0] == "!Remove" {
						err = deleteFileFromDB(key)
						if err != nil {
							http.Error(res, err.Error(), http.StatusInternalServerError)
							context.Clear(req)
							return
						}

						err = os.Remove("assets/photos/" + key)
						if err != nil {
							http.Error(res, err.Error(), http.StatusInternalServerError)
							context.Clear(req)
							return
						}

					} else {
						if _, err := os.Stat("assets/photos/" + key); os.IsNotExist(err) {
							context.Clear(req)
							io.WriteString(res,
								"<script>window.alert('Update impossible: file removed in another session.')</script>")
							http.Redirect(res, req, "/", http.StatusGone)
						} else {
							tags := map[string][]string{
								key: value,
							}
							err = storeFilesToDB(tags)
							if err != nil {
								http.Error(res, err.Error(), http.StatusInternalServerError)
								context.Clear(req)
								return
							}
						}
					}
				}
			}
			context.Clear(req)
			http.Redirect(res, req, "/", http.StatusSeeOther)
			// return
		}

		pbod.Name = session.Values["name"].(string)

		tmplt, err = template.ParseFiles("templates/logged_head.html")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}

		err = tmplt.Execute(res, pbod)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}
		// return

	case "":
		if req.Method == "POST" {
			req.ParseForm()

			var pwd []byte
			var islogin string

			for key, value := range req.Form {
				switch key {
				case "uname":
					islogin = strings.ToLower(value[0])
				case "pwd":
					pwd = []byte(value[0])
				default:
					context.Clear(req)
					io.WriteString(res, "<script>window.alert('Session expired.')</script>")
					http.Redirect(res, req, "/", http.StatusConflict)
				}
			}

			userstruct, err := getUserFromDB(islogin)
			if err != nil {
				http.Error(res, err.Error(), http.StatusInternalServerError)
				context.Clear(req)
				return
			}

			shapass := fmt.Sprintf("%x", sha256.Sum256(append(pwd, userstruct.Salt...)))
			storedpass := fmt.Sprintf("%x", userstruct.PassSha)

			if shapass == storedpass && islogin == userstruct.Name && userstruct.Name != "" {

				pbod.Name = islogin

				session.Values["name"] = islogin
				session.Values["pwd"] = shapass
				session.Options.MaxAge = 5000

				session.Save(req, res)

				http.Redirect(res, req, "/", http.StatusSeeOther)

			} else if shapass != storedpass && islogin != "" {

				pbod.Name = "Wrong username/password"

				tmplt, err = template.ParseFiles("templates/unlogged_head.html")
				if err != nil {
					http.Error(res, err.Error(), http.StatusInternalServerError)
					context.Clear(req)
					return
				}

				err = tmplt.Execute(res, pbod)
				if err != nil {
					http.Error(res, err.Error(), http.StatusInternalServerError)
					context.Clear(req)
					return
				}
				context.Clear(req)
				return
			}
			context.Clear(req)
		}

		tmplt, err = template.ParseFiles("templates/unlogged_head.html")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}

		err = tmplt.Execute(res, pbod)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}

	}
}

func uploadsHandler(res http.ResponseWriter, req *http.Request) {

	session, _ := store.Get(req, "admin")
	// if err != nil {
	// 	http.Error(res, err.Error(), http.StatusInternalServerError)
	// 	context.Clear(req)
	// 	return
	// }
	var userstruct User

	if session.Values["name"] != nil {
		var err error
		userstruct, err = getUserFromDB(session.Values["name"].(string))
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}
	}

	storedpass := fmt.Sprintf("%x", userstruct.PassSha)

	if session.Values["name"] == nil || session.Values["pwd"] == nil || session.Values["pwd"].(string) != storedpass {
		session.Values["name"] = ""
		session.Values["pwd"] = ""
	}

	if session.Values["name"].(string)+session.Values["pwd"].(string) == userstruct.Name+storedpass {

		db, err := bolt.Open("db/data.db", 0644, nil)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}

		alltags := []string{}

		db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("Files"))
			if b == nil {
				return nil
			}
			c := b.Cursor()

			for k, v := c.First(); k != nil; k, v = c.Next() {
				var filetags []string
				err := json.Unmarshal(v, &filetags)
				if err != nil {
					return err
				}
				alltags = dedupe(append(alltags, filetags...))
			}

			return nil
		})

		db.Close()

		tagsjson, err := json.Marshal(map[string][]string{
			"alltags": alltags,
		})

		pbod := PageBody{
			Name:  session.Values["name"].(string),
			Files: template.JS(tagsjson),
		}

		if req.Method == "POST" {
			err := req.ParseMultipartForm(200000) // grab the multipart form
			if err != nil {
				http.Error(res, err.Error(), http.StatusInternalServerError)
				context.Clear(req)
				return
			}

			formdata := req.MultipartForm // ok, no problem so far, read the Form data

			//get the *fileheaders
			files := formdata.File["multiplefiles"] // grab the filenames
			tags := formdata.Value

			uploaded := "<script>window.alert('Photos uploaded')</script>"

			for i, _ := range files {

				filename := files[i].Filename

				go resizeAndSave(files[i], filename, saveErrchan)

				fsaveErr := <-saveErrchan
				if fsaveErr != nil {
					http.Error(res, err.Error(), http.StatusInternalServerError)
					context.Clear(req)
					return
				}

			}

			err = storeFilesToDB(tags)

			if err != nil {
				http.Error(res, err.Error(), http.StatusInternalServerError)
				context.Clear(req)
				return
			}

			context.Clear(req)
			io.WriteString(res, uploaded)
		}

		tmplt, err := template.ParseFiles("templates/upload.html")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}

		err = tmplt.Execute(res, pbod)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			context.Clear(req)
			return
		}

	} else {
		context.Clear(req)
		http.Redirect(res, req, "/", http.StatusSeeOther)
	}
}
