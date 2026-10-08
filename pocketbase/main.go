package main

import (
	"github.com/pocketbase/pocketbase"
	"log"
	"myapp/gateway"
	_ "myapp/migrations"
)

func main() {
	app := pocketbase.New()
	config, err := gateway.ConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	runtime := gateway.New(app, config)
	runtime.Register()
	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
