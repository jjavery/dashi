package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"jjavery/dashi"
	"log"
	"os"
	"runtime/debug"

	"golang.org/x/term"
)

// var identity, _ = dashi.NewIdentityFromSecretKeyString(
// 	"4PTEBTQXOEM32MGN5LO55FVUGYJXN6U6HQ5Y3FKLBVVRUALMR2N3NJKHW5JT76ASLSSNUWEDB5O66HA6LSYKJB3NSIAJ2PQWSDC6P4Q")
var r3Identity, _ = dashi.NewIdentityFromSecretKeyString(
	"PSC5XDCRXXT47CBYWWOQM2ZMMGKDR562XXQOV52HGDM7CW3VHSJ32CJJKMUZRHUZ7ZTXQOJZIWPCIN5D24O7RHDLK4RI233WZGDGBGQ")

var r1, _ = dashi.NewRecipientFromPublicKeyString("TVGC5UIZ47WOBRJS7QIZPD3FEOZ5ZLQNUVXYIP4APFSUHUFCSYBQ")
var r2, _ = dashi.NewRecipientFromPublicKeyString("E42442EKFHZXIZBWPVIEJZQJOBTSS6X6RJ7446GUF7A6QO274SYQ")
var r3, _ = dashi.NewRecipientFromPublicKeyString("XUESSUZJTCPJT7THPA4TSRM6EQ32HVY57COGWVZCRVXXNSMGMCNA")

type multiFlag []string

func (f *multiFlag) String() string { return fmt.Sprint(*f) }

func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

const usage = `Usage:
    dashi --keygen [-o OUTPUT]
    dashi [--encrypt] [-i PATH] (-r RECIPIENT | -R PATH)... [--armor] [-o OUTPUT] [INPUT]
    dashi --decrypt [-i PATH]... [-o OUTPUT] [INPUT]
    dashi --sign [-o OUTPUT] [INPUT]
    dashi --verify [INPUT]

Options:
    -k, --keygen                Generate a key pair.
    -e, --encrypt               Encrypt the input to the output.
    -d, --decrypt               Decrypt the input to the output. Default if omitted.
    -s, --sign                  Sign the input to the output.
    -v, --verify                Verify the input.
    -o, --output OUTPUT         Write the result to the file at path OUTPUT.
    -a, --armor                 Encrypt/sign to a Base64 encoded format.
    -r, --recipient RECIPIENT   Encrypt to the specified RECIPIENT. Can be repeated.
    -R, --recipients-file PATH  Encrypt to recipients listed at PATH. Can be repeated.
    -i, --identity PATH         Use the identity file at PATH. Can be repeated with
		                            decrypt or verify.
    -n, --anon                  Encrypt to anonymous recipients with an anonymous
                                identity.

INPUT defaults to standard input, and OUTPUT defaults to standard output.
If OUTPUT exists, it will be overwritten.

RECIPIENT is a dashi public key generated with dashi --keygen

Recipient files contain one or more recipients, one per line. "-" may be used to
read recipients from standard input.

Identity files contain one or more secret keys ("Secret-Key: ..."),
one per line. Multiple key files can be provided, and any unused ones
will be ignored. "-" may be used to read identities from standard input.

Example:
    $ dashi --keygen -o key.txt
    Public-Key: 58Jrd91MvzPqJEVty1ZBfqBwFyfdS31Eee48irrKSjw
    $ tar cvz ~/data | dashi -r 58Jrd91MvzPqJEVty1ZBfqBwFyfdS31Eee48irrKSjw > data.tar.gz.dashi
    $ dashi --decrypt -i key.txt -o data.tar.gz data.tar.gz.dashi`

var Version string
var stdinInUse bool

const defaultIdentityFile = "~/.dashi/identity"

func main() {
	log.SetFlags(0)
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var (
		outFlag                       string
		keygenFlag                    bool
		decryptFlag, encryptFlag      bool
		versionFlag, armorFlag        bool
		signFlag, verifyFlag          bool
		recipientFlags, identityFlags multiFlag
		recipientsFileFlags           multiFlag
		// passFlag                      bool
	)

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(1)
	}

	flag.BoolVar(&versionFlag, "version", false, "print the version")
	flag.BoolVar(&keygenFlag, "k", false, "generate a key pair")
	flag.BoolVar(&keygenFlag, "keygen", false, "generate a key pair")
	flag.BoolVar(&encryptFlag, "e", false, "encrypt the input")
	flag.BoolVar(&encryptFlag, "encrypt", false, "encrypt the input")
	flag.BoolVar(&decryptFlag, "d", false, "decrypt the input")
	flag.BoolVar(&decryptFlag, "decrypt", false, "decrypt the input")
	flag.BoolVar(&signFlag, "s", false, "sign the input")
	flag.BoolVar(&signFlag, "sign", false, "sign the input")
	flag.BoolVar(&verifyFlag, "v", false, "verify the input")
	flag.BoolVar(&verifyFlag, "verify", false, "verify the input")
	// flag.BoolVar(&passFlag, "p", false, "use a passphrase")
	// flag.BoolVar(&passFlag, "passphrase", false, "use a passphrase")
	flag.StringVar(&outFlag, "o", "", "output to `FILE` (default stdout)")
	flag.StringVar(&outFlag, "output", "", "output to `FILE` (default stdout)")
	flag.BoolVar(&armorFlag, "a", false, "generate an armored file")
	flag.BoolVar(&armorFlag, "armor", false, "generate an armored file")
	flag.Var(&recipientFlags, "r", "recipient (can be repeated)")
	flag.Var(&recipientFlags, "recipient", "recipient (can be repeated)")
	flag.Var(&recipientsFileFlags, "R", "recipients file (can be repeated)")
	flag.Var(&recipientsFileFlags, "recipients-file", "recipients file (can be repeated)")
	flag.Var(&identityFlags, "i", "identity (can be repeated)")
	flag.Var(&identityFlags, "identity", "identity (can be repeated)")
	flag.Parse()

	if versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}

	if flag.NArg() > 1 {
		errorWithHint(fmt.Sprintf("too many arguments: %q", flag.Args()),
			"note that the input file must be specified after all flags")
	}
	switch {
	case keygenFlag:
	case decryptFlag:
		if encryptFlag {
			errorf("-e/--encrypt can't be used with -d/--decrypt")
		}
		if armorFlag {
			errorWithHint("-a/--armor can't be used with -d/--decrypt",
				"note that armored files are detected automatically")
		}
		// if passFlag {
		// 	errorWithHint("-p/--passphrase can't be used with -d/--decrypt",
		// 		"note that password protected files are detected automatically")
		// }
		if len(recipientFlags) > 0 {
			errorWithHint("-r/--recipient can't be used with -d/--decrypt",
				"did you mean to use -i/--identity to specify a private key?")
		}
		if len(recipientsFileFlags) > 0 {
			errorWithHint("-R/--recipients-file can't be used with -d/--decrypt",
				"did you mean to use -i/--identity to specify a private key?")
		}
	default: // encrypt
		// if len(identityFlags) > 0 && !encryptFlag {
		// 	errorWithHint("-i/--identity can't be used in encryption mode unless symmetric encryption is explicitly selected with -e/--encrypt",
		// 		"did you forget to specify -d/--decrypt?")
		// }
		if len(identityFlags) == 0 {
			if !fileExists(defaultIdentityFile) {
				errorWithHint("-i/--identity is required with -e/--encrypt",
					"or create a default identity file in '"+defaultIdentityFile+"'")
			}
		}
		if len(identityFlags) > 1 {
			errorWithHint("multiple -i/--identity arguments can't be used with -e/--encrypt",
				"did you mean to use -d/--decrypt?")
		}
		if len(recipientFlags)+len(recipientsFileFlags) == 0 /*&& !passFlag*/ {
			errorWithHint("missing recipients",
				// "did you forget to specify -r/--recipient, -R/--recipients-file or -p/--passphrase?")
				"did you forget to specify -r/--recipient, -R/--recipients-file?")
		}
		// if len(recipientFlags) > 0 && passFlag {
		// 	errorf("-p/--passphrase can't be combined with -r/--recipient")
		// }
		// if len(recipientsFileFlags) > 0 && passFlag {
		// 	errorf("-p/--passphrase can't be combined with -R/--recipients-file")
		// }
		// if len(identityFlags) > 0 && passFlag {
		// 	errorf("-p/--passphrase can't be combined with -i/--identity")
		// }
	}

	var in io.Reader = os.Stdin
	var out io.Writer = os.Stdout
	if name := flag.Arg(0); name != "" && name != "-" {
		f, err := os.Open(name)
		if err != nil {
			errorf("failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		in = f
	} else {
		stdinInUse = true
	}
	if name := outFlag; name != "" && name != "-" {
		f := newLazyOpener(name)
		defer func() {
			if err := f.Close(); err != nil {
				errorf("failed to close output file %q: %v", name, err)
			}
		}()
		out = f
	} else if term.IsTerminal(int(os.Stdout.Fd())) {
		if name != "-" {
			if decryptFlag || keygenFlag {
				// TODO: buffer the output and check it's printable.
			} else if !armorFlag {
				// If the output wouldn't be armored, refuse to send binary to
				// the terminal unless explicitly requested with "-o -".
				errorWithHint("refusing to output binary to the terminal",
					"did you mean to use -a/--armor?",
					`force anyway with "-o -"`)
			}
		}
		if in == os.Stdin && term.IsTerminal(int(os.Stdin.Fd())) {
			// If the input comes from a TTY and output will go to a TTY,
			// buffer it up so it doesn't get in the way of typing the input.
			buf := &bytes.Buffer{}
			defer func() { io.Copy(os.Stdout, buf) }()
			out = buf
		}
	}

	switch {
	case keygenFlag:
		generateKey(out)
	case decryptFlag:
		decrypt(identityFlags, in, out)
	// case passFlag:
	// 	pass, err := passphrasePromptForEncryption()
	// 	if err != nil {
	// 		errorf("%v", err)
	// 	}
	// 	encryptPass(pass, in, out, armorFlag)
	default:
		encrypt(recipientFlags, recipientsFileFlags, identityFlags, in, out, armorFlag)
	}

	// err := run()
	// if err != nil {
	// 	log.Fatal(err)
	// }
}

// func run() error {
// 	err := generateKey()
// 	if err != nil {
// 		return err
// 	}

// 	err = encrypt()
// 	if err != nil {
// 		return err
// 	}

// 	err = decrypt()
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

func encrypt(recipientKeys, recipientFiles, identityFiles []string,
	in io.Reader, out io.Writer, armor bool) {

	var recipients []dashi.Recipient
	var identities []dashi.Identity

	for _, publicKey := range recipientKeys {
		recipient, err := dashi.NewRecipientFromPublicKeyString(publicKey)
		if err != nil {
			errorf("%v", err)
		}
		recipients = append(recipients, *recipient)
	}
	for _, path := range recipientFiles {
		r, err := parseRecipientsFile(path)
		if err != nil {
			errorf("failed to parse recipient file %q: %v", path, err)
		}
		recipients = append(recipients, r...)
	}
	for _, path := range identityFiles {
		i, err := parseIdentitiesFile(path)
		if err != nil {
			errorf("reading %q: %v", path, err)
		}
		identities = append(identities, i...)
	}

	err := dashi.Encrypt(identities[0], recipients, in, out)
	if err != nil {
		errorf("%v", err)
	}
}

func decrypt(identityFiles []string, in io.Reader, out io.Writer) {
	var identities []dashi.Identity

	for _, path := range identityFiles {
		i, err := parseIdentitiesFile(path)
		if err != nil {
			errorf("reading %q: %v", path, err)
		}
		identities = append(identities, i...)
	}

	err := dashi.Decrypt(identities, in, out)
	if err != nil {
		errorf("%v", err)
	}
}

func generateKey(out io.Writer) error {
	return dashi.GenerateKey(out)
}

func parseRecipientsFile(path string) ([]dashi.Recipient, error) {
	return []dashi.Recipient{
		*r1,
		*r2,
		*r3,
	}, nil
}

func parseIdentitiesFile(path string) ([]dashi.Identity, error) {
	return []dashi.Identity{
		*r3Identity,
	}, nil
}

type lazyOpener struct {
	name string
	f    *os.File
	err  error
}

func newLazyOpener(name string) io.WriteCloser {
	return &lazyOpener{name: name}
}

func (l *lazyOpener) Write(p []byte) (n int, err error) {
	if l.f == nil && l.err == nil {
		l.f, l.err = os.Create(l.name)
	}
	if l.err != nil {
		return 0, l.err
	}
	return l.f.Write(p)
}

func (l *lazyOpener) Close() error {
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	if err == nil {
		return true
	}
	return false
}

func errorf(format string, v ...interface{}) {
	log.Fatalf("dashi: error: "+format, v...)
}

func warningf(format string, v ...interface{}) {
	log.Printf("dashi: warning: "+format, v...)
}

func errorWithHint(error string, hints ...string) {
	log.Printf("dashi: error: %s", error)
	for _, hint := range hints {
		log.Printf("dashi: hint: %s", hint)
	}
	os.Exit(1)
}
