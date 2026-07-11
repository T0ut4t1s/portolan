// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// cmdHashpw prints a "username:bcrypthash" line for the serve --auth-users-file.
// The password is read from stdin — prompted with no echo when stdin is a
// terminal, or read as the first line when piped (e.g. from a secret manager).
func cmdHashpw(args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: portolan hashpw <username>\n" +
			"  reads the password from stdin (prompts if interactive) and prints a\n" +
			"  'username:bcrypthash' line for serve --auth-users-file")
	}
	user := args[0]
	if strings.ContainsAny(user, ":\n") {
		return fmt.Errorf("username must not contain ':' or a newline")
	}

	var pw []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pw = p
	} else {
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			pw = []byte(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return err
		}
	}
	if len(pw) == 0 {
		return fmt.Errorf("empty password")
	}

	hash, err := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Printf("%s:%s\n", user, hash)
	return nil
}
