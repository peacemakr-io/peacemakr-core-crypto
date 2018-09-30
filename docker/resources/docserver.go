package main

import (
  "os"
  "log"
  "net/http"
)

func main() {
  fs := http.FileServer(http.Dir(os.Getenv("DOC_DIR") + "/html"))
  http.Handle("/", fs)

  log.Println("Listening on port 3000...")
  http.ListenAndServe(":3000", nil)
}
