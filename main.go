package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/dncohen/qpass/gohash_db"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh/terminal"
)

// exit gracefully if ctrl-C during password prompt
// https://groups.google.com/forum/#!topic/golang-nuts/kTVAbtee9UA
var initialState *terminal.State

var idleSec uint // password required after inactivity

func init() {
	log.SetOutput(ioutil.Discard)
	log.SetFlags(0)

	// remember initial terminal state
	var err error
	if initialState, err = terminal.GetState(syscall.Stdin); err != nil {
		return
	}

	// and restore it on exit
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		<-c
		println("")
		_ = terminal.Restore(syscall.Stdin, initialState)
		os.Exit(0)
	}()
}

func getGoHashFilePath() string {
	home, err := homedir.Expand("~/.go-hash")
	if err != nil {
		panic(err)
	}
	return home
}

func parentDirExists(path string) bool {
	_, err := os.Stat(filepath.Dir(path))
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	panic("Cannot read directory path")
}

func isDir(path string) bool {
	stat, err := os.Stat(path)
	if err == nil {
		return stat.IsDir()
	}
	return false
}

func createPassword() string {
	for i := 0; i < 10; i++ {
		print("Enter a master password: ")
		pass, err := terminal.ReadPassword(int(syscall.Stdin))
		println("")
		if err != nil {
			panic(err)
		}
		if len(pass) > 0 {
			if len(pass) < 7 {
				fmt.Println("You've chosen a short (insecure) master password.  Just testing? I hope so.")
			}

			print("Confirm the master password: ")
			pass2, err := terminal.ReadPassword(int(syscall.Stdin))
			println("")
			if err != nil {
				panic(err)
			}
			if len(pass2) == 0 {
				break
			}
			if bytes.Equal(pass, pass2) {
				return string(pass)
			}
			println("Password mismatch, try again.")
		} else {
			println("A password is required.")
		}
	}
	fmt.Println("This is just isn't going to work out.")
	os.Exit(1)
	return ""
}

func openDatabase(dbFilePath string) (state State, userPass string) {
	for i := 0; i < 5; i++ {
		print("Master password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		println("")
		if err != nil {
			panic(err)
		}
		userPass = string(bytePassword)
		state, err = gohash_db.ReadDatabase(dbFilePath, userPass)
		if err != nil {
			println("Error: " + err.Error())
		} else {
			return
		}
	}
	fmt.Println("Too many attempts!")
	os.Exit(1)
	return
}

func splitTrimN(text string, max int) []string {
	result := make([]string, max)
	parts := strings.SplitN(text, " ", max)
	for i, c := range parts {
		result[i] = strings.TrimSpace(c)
	}
	return result
}

func runCliLoop(state *State, dbPath string, userPass string) {
	grBox := stringBox{value: "default"}
	mpBox := stringBox{value: userPass}
	userPass = ""
	reader := bufio.NewReader(os.Stdin)
	prompt := func() string {
		var modifier string
		if len(grBox.value) > 0 && grBox.value != "default" {
			modifier = ":" + grBox.value
		}
		return fmt.Sprintf("\033[31m%s%s »\033[0m ", dbPath, modifier)
	}

	commands := createCommands(state, &grBox, &mpBox)

	cli, err := readline.NewEx(&readline.Config{
		Prompt:          prompt(),
		AutoComplete:    createCompleter(commands),
		InterruptPrompt: "^C",
	})
	if err != nil {
		panic(err)
	}
	defer cli.Close()

	eofCount := 0
	idleSince := time.Now()
	passwordTimeout := time.Duration(idleSec) * time.Second

Loop:
	for {
		cli.SetPrompt(prompt())
		line, err := cli.Readline()
		if err != nil {
			switch err {
			case readline.ErrInterrupt:
				if len(line) == 0 {
					println("Warning: Received interrupt, exiting.")
					break Loop
				}
				continue
			case io.EOF:
				eofCount++
				if eofCount > 10 { // protect against infinite loop
					panic("EOF received several times unexpectedly!")
				}
				continue // in Windows, we get EOFs all the time
			default:
				panic(err)
			}
		}

		eofCount = 0

		parts := splitTrimN(line, 2)
		cmd := parts[0]
		args := parts[1]

		switch cmd {
		case "quit":
			break Loop
		case "exit":
			if grBox.value != "default" {
				grBox.value = "default"
			} else {
				break Loop
			}
		default:
			command := commands[cmd]
			if command != nil {

				deltaT := time.Now().Sub(idleSince)
				if cmd != "cmp" && cmd != "help" { // cmp will prompt for password every time, help is not sensitive
					if idleSec > 0 && deltaT > passwordTimeout {
						// prompt for password before allowing command to run
						fmt.Printf("password required (idle %s)\n", deltaT.Round(time.Second))
						print("master password: ")
						pass, err := terminal.ReadPassword(int(syscall.Stdin))
						println("")
						if err != nil {
							println("error:", err)
							continue Loop
						}
						if string(pass) != mpBox.value {
							println("error: password mismatch")
							continue Loop
						}
					}
					idleSince = time.Now()
				}

				command.run(state, grBox.value, args, reader)
				err = gohash_db.WriteDatabase(dbPath, mpBox.value, state)
				if err != nil {
					println("Error writing to database: " + err.Error())
				}
			} else if len(cmd) > 0 {
				fmt.Printf("Unknown command: '%s'. Type 'help' for usage.\n", cmd)
			}
		}
	}
}

func main() {
	var userPass string
	var state State
	fmt.Printf("%s (db version: %s)\n\n", os.Args[0], gohash_db.DBVersion) // verbose

	var dbFilePath string
	flag.UintVar(&idleSec, "idle", 60, "password timeout, in seconds (use 0 for no timeout)")
	flag.StringVar(&dbFilePath, "db", getGoHashFilePath(), "file where password data is stored")
	flag.Parse()

	if !parentDirExists(dbFilePath) {
		fmt.Printf("Directory not found (%s)\n\n", filepath.Dir(dbFilePath))
		os.Exit(2)
	}
	if isDir(dbFilePath) {
		fmt.Printf("File not found (%s): path is a directory\n\n", dbFilePath)
		os.Exit(2)
	}

	if len(flag.Args()) > 0 {
		fmt.Printf("usage: %s [-db <database filename>] [-idle <password timeout>]", os.Args[0])
		os.Exit(2)
	}

	dbFile, err := os.Open(dbFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("creating new password database (%s)\n", dbFilePath)
			userPass = createPassword()
		} else {
			panic(err)
		}
		state = make(State)
	} else {
		// the DB exists, check if the user can open it
		dbFile.Close()
		state, userPass = openDatabase(dbFilePath)
	}

	if len(state) == 0 {
		state["default"] = []LoginInfo{}
	}

	runCliLoop(&state, dbFilePath, userPass)
}
