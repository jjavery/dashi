package main

import (
	"fmt"
	"jjavery/dashi"
	"os"
)

var identity, _ = dashi.NewIdentityFromSecretKeyString(
	"2mzAkBK5EDYHlYsWHCumPHeOUNDf+PKCAwmWvMxhRTQ3TByRICn0BpZenwugsNq01nAiYKu4RdH7xzdtTT9h3w")
var r3Identity, _ = dashi.NewIdentityFromSecretKeyString(
	"tWUZdePBOKLCtr8Zb6SlBmHmyzFF3Ub516rMtiqNGW/nwmt33Uy/M+okRW3LVkF+oHAXJ91LfUR57jyKuspKPA")

var r1, _ = dashi.NewRecipientFromPublicKeyString("aK45GX7RrMzpk7wWKvx3Gc9K7xyYe2kY9UD0aw0dObU")
var r2, _ = dashi.NewRecipientFromPublicKeyString("g4am+iU1y852JOohC/+JzN2ssSzdT/eWGL5Onw7u0fA")
var r3, _ = dashi.NewRecipientFromPublicKeyString("58Jrd91MvzPqJEVty1ZBfqBwFyfdS31Eee48irrKSjw")

var recipients = []dashi.Recipient{
	// *r1,
	// *r2,
	*r3,
}

func main() {
	err := run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	err := generateKey()
	if err != nil {
		return err
	}

	err = encrypt()
	if err != nil {
		return err
	}

	err = decrypt()
	if err != nil {
		return err
	}

	return nil
}

func encrypt() (err error) {
	in, err := os.Open("/Users/jamie/Projects/dashi/test.txt")
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create("/Users/jamie/Projects/dashi/test.enc")
	if err != nil {
		return err
	}
	defer out.Close()

	// in := os.Stdin
	// out := os.Stdout

	err = dashi.Encrypt(*identity, recipients, in, out)

	return err
}

func decrypt() (err error) {
	identities := []dashi.Identity{
		*r3Identity,
	}

	in, err := os.Open("/Users/jamie/Projects/dashi/test.enc")
	if err != nil {
		return err
	}
	defer in.Close()

	out := os.Stdout

	err = dashi.Decrypt(identities, in, out)

	return err
}

func generateKey() error {
	out, err := os.Create("/Users/jamie/Projects/dashi/test.secret")
	if err != nil {
		return err
	}
	defer out.Close()

	err = dashi.GenerateKey(out)

	return err
}
