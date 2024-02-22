package main

import (
	"fmt"
	"log"

	"github.com/mohammedfuta2000/csrf-project/db"
	"github.com/mohammedfuta2000/csrf-project/server"
	"github.com/mohammedfuta2000/csrf-project/server/middleware/myJwt"
)


var (
	host = "localhost"
	port = "9000"
)
func main()  {
	db.InitDB()

	jwtErr:=myJwt.InitJWT()

	if jwtErr!=nil {
		fmt.Println("Error initializing JWT!")
		log.Fatal(jwtErr)
	}

	serverErr:=server.StartServer(host,port)
	if serverErr!=nil {
		fmt.Println("Error starting Server!")
		log.Fatal(serverErr)
	}
}