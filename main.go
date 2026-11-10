package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "loopback address to listen on")
	open := flag.Bool("open", true, "open the page in the default browser")
	flag.Parse()

	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal("address must look like 127.0.0.1:0")
	}
	if !loopbackHost(host) {
		log.Fatal("refusing to listen outside 127.0.0.1")
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		log.Fatal(err)
	}
	url := "http://" + ln.Addr().String() + "/"

	srv := &http.Server{
		Handler:           handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Println("Config Obfuscator")
	fmt.Println(url)
	fmt.Println("The config stays in the browser. This program only serves the page.")
	fmt.Println("Close this window to quit.")

	if *open {
		if err := openBrowser(url); err != nil {
			fmt.Println("Open that address in a browser.")
		}
	}

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
