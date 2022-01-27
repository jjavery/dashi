package main

import (
	"jjavery/dashi"
	"log"
	"os"
)

var identity, _ = dashi.NewIdentity("tWu0FvL0W3o7Ruilhqxf6J+siu/+LMCnb/wETR8ArJIk5hWO9xVYGXpl9kJ51rWfSwo+0/jdk8y7oaABpqJqmw")

var r1, _ = dashi.NewRecipient("aK45GX7RrMzpk7wWKvx3Gc9K7xyYe2kY9UD0aw0dObU")
var r2, _ = dashi.NewRecipient("g4am+iU1y852JOohC/+JzN2ssSzdT/eWGL5Onw7u0fA")
var r3, _ = dashi.NewRecipient("ga1pEbF8GSiF38q0Vwg8HtJOAR+rnyjznLnJ/gCOWRs")

var recipients = []dashi.Recipient{
	*r1,
	*r2,
	*r3,
}

func main() {
	err := encrypt()
	if err != nil {
		log.Fatal(err)
	}

	// err = decrypt()
	// if err != nil {
	// 	log.Fatal(err)
	// }
}

func encrypt() (err error) {
	// dir, err := os.Getwd()
	// if err != nil {
	// 	return err
	// }

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
	// dir, err := os.Getwd()
	// if err != nil {
	// 	return err
	// }

	identities := []dashi.Identity{
		*identity,
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
