package main

import "errors"

func cmdAutoconfig([]string) error { return errors.New("autoconfig is for Linux and BSD servers") }

func maybeAutoconfigure() bool { return false }
