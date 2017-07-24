# nafotal
Photogallery website I initially made for myself.
Backend written on Golang, frontend built around [Isotope](https://github.com/metafizzy/isotope) jQuery library.

## Dependencies
### For backend
https://golang.org/x/crypto/acme/autocert

https://github.com/boltdb/bolt

https://github.com/gorilla/context

https://github.com/gorilla/sessions

https://gopkg.in/h2non/bimg.v1

Also **libvips** should be installed prior code compillation.

### For frontend
https://github.com/jquery/jquery

https://github.com/desandro/imagesloaded

https://github.com/metafizzy/isotope

https://github.com/KhaledElAnsari/RESTInTag

You should put these libs to `assets/js/` dir or edit html templates to use them online (visit projects pages for further info).

## First run
First of all you should write your domain name to `certManager` in `main.go` or get rid of TLS at all.
After compiling main.go you'd be able to visit empty gallery. To add user/users who would upload photos to website you have to compile `usrupd.go` utility.

## usrupd
This util made to manage website admins. Run it with `-adduser=username` flag to add new admin, `-delete=username` to delete and `list` arg to show all admins.

## Notes
Images dosen't keep the order and shown as they load by intention. To change this behaviour visit Isotope web-page FAQ.
Cookies invalidates on every server restart as new cookie store secret key generated on every init.
Photos are resize on upload with **libvips**.
