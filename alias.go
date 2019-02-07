package main

import("github.com/dncohen/qpass/gohash_db")

// These lines are in their own file, because they cause problems for `go fmt`.

// State local alias
type State = gohash_db.State

// LoginInfo local alias
type LoginInfo = gohash_db.LoginInfo
