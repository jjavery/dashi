package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"jjavery/dashi"
	"jjavery/dashi/internal/header"
	"log"
	"net/textproto"
	"os"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strings"
	"unicode"

	"golang.org/x/term"
)

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

var defaultIdentityFile = ".dashi/identity"

func main() {
	usr, _ := user.Current()
	defaultIdentityFile = filepath.Join(usr.HomeDir, defaultIdentityFile)

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
		if encryptFlag {
			errorf("-e/--encrypt can't be used with -k/--keygen")
		}
		if decryptFlag {
			errorf("-d/--decrypt can't be used with -k/--keygen")
		}
		if signFlag {
			errorf("-s/--sign can't be used with -k/--keygen")
		}
		if verifyFlag {
			errorf("-v/--verify can't be used with -k/--keygen")
		}
		if armorFlag {
			errorWithHint("-a/--armor can't be used with -k/--keygen")
		}
	case signFlag:
		if encryptFlag {
			errorf("-e/--encrypt can't be used with -s/--sign")
		}
		if decryptFlag {
			errorf("-d/--decrypt can't be used with -s/--sign")
		}
		if verifyFlag {
			errorf("-v/--verify can't be used with -s/--sign")
		}
		if armorFlag {
			errorWithHint("-a/--armor can't be used with -s/--sign")
		}
		if len(identityFlags) == 0 {
			if !fileExists(defaultIdentityFile) {
				errorWithHint("-i/--identity is required with -s/--sign",
					"or create a default identity file in '"+defaultIdentityFile+"'")
			}
			identityFlags = append(identityFlags, defaultIdentityFile)
		}
		if len(identityFlags) > 1 {
			errorWithHint("multiple -i/--identity arguments can't be used with -s/--sign",
				"did you mean to use -d/--decrypt?")
		}
	case verifyFlag:
		if encryptFlag {
			errorf("-e/--encrypt can't be used with -v/--verify")
		}
		if decryptFlag {
			errorf("-d/--decrypt can't be used with -v/--verify")
		}
		if armorFlag {
			errorWithHint("-a/--armor can't be used with -v/--verify")
		}
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
			identityFlags = append(identityFlags, defaultIdentityFile)
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
	} else if verifyFlag {
		out = ioutil.Discard
	} else if term.IsTerminal(int(os.Stdout.Fd())) {
		if name != "-" {
			if decryptFlag || keygenFlag || verifyFlag {
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
	case signFlag:
		sign(identityFlags, in, out)
	case verifyFlag:
		verify(recipientFlags, recipientsFileFlags, in, out)
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
}

func generateKey(out io.Writer) error {
	return dashi.GenerateKey(out)
}

func sign(identityFiles []string, in io.Reader, out io.Writer) {
	var identities []dashi.Identity

	for _, name := range identityFiles {
		i, err := parseIdentitiesFile(name)
		if err != nil {
			errorf("reading %q: %v", name, err)
		}
		identities = append(identities, i...)
	}

	err := dashi.Sign(identities[0], in, out)
	if err != nil {
		errorf("%v", err)
	}
}

func verify(recipientKeys, recipientFiles []string,
	in io.Reader, out io.Writer) {

	var recipients []dashi.Recipient

	for _, publicKey := range recipientKeys {
		recipient, err := dashi.NewRecipientFromPublicKeyString(publicKey)
		if err != nil {
			errorf("%v", err)
		}
		recipients = append(recipients, *recipient)
	}
	for _, name := range recipientFiles {
		r, err := parseRecipientsFile(name)
		if err != nil {
			errorf("failed to parse recipient file %q: %v", name, err)
		}
		recipients = append(recipients, r...)
	}

	err := dashi.Verify(recipients[0], in, out)
	if err != nil {
		errorf("%v", err)
	}
}

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
	for _, name := range recipientFiles {
		r, err := parseRecipientsFile(name)
		if err != nil {
			errorf("failed to parse recipient file %q: %v", name, err)
		}
		recipients = append(recipients, r...)
	}
	for _, name := range identityFiles {
		i, err := parseIdentitiesFile(name)
		if err != nil {
			errorf("reading %q: %v", name, err)
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

	for _, name := range identityFiles {
		i, err := parseIdentitiesFile(name)
		if err != nil {
			errorf("reading %q: %v", name, err)
		}
		identities = append(identities, i...)
	}

	err := dashi.Decrypt(identities, in, out)
	if err != nil {
		errorf("%v", err)
	}
}

func parseRecipientsFile(name string) ([]dashi.Recipient, error) {
	file, err := openFile(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := bufio.NewReader(file)

	tpReader := textproto.NewReader(buf)

	mimeHeader, err := tpReader.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, err
	}

	publicKeyHeaders := mimeHeader.Values("Public-Key")
	if len(publicKeyHeaders) == 0 {
		return nil, fmt.Errorf("file does not contain a public key: %v", name)
	}

	var recipients []dashi.Recipient

	for _, publicKeyHeader := range publicKeyHeaders {
		if publicKeyHeader == "" {
			return nil, fmt.Errorf("public key is required")
		}

		publicKeyHeaderFields := strings.Fields(publicKeyHeader)
		l := len(publicKeyHeaderFields)
		if l != 2 {
			return nil, fmt.Errorf("invalid public key format")
		}
		if publicKeyHeaderFields[0] != string(header.Ed25519) {
			return nil, fmt.Errorf("unknown public key type")
		}

		publicKeyString := publicKeyHeaderFields[1]

		if len(publicKeyString) != 52 {
			return nil, fmt.Errorf("invalid public key length")
		}

		recipient, err := dashi.NewRecipientFromPublicKeyString(publicKeyString)
		if err != nil {
			return nil, err
		}

		recipients = append(recipients, *recipient)
	}

	return recipients, nil
}

func parseIdentitiesFile(name string) ([]dashi.Identity, error) {
	file, err := openFile(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := bufio.NewReader(file)

	tpReader := textproto.NewReader(buf)

	mimeHeader, err := tpReader.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, err
	}

	secretKeyHeaders := mimeHeader.Values("Secret-Key")
	if len(secretKeyHeaders) == 0 {
		return nil, fmt.Errorf("identity file does not contain a secret key: %v", name)
	}

	var identities []dashi.Identity

	for _, secretKeyHeader := range secretKeyHeaders {
		if secretKeyHeader == "" {
			return nil, fmt.Errorf("secret key is required")
		}

		secretKeyHeaderFields := strings.Fields(secretKeyHeader)
		l := len(secretKeyHeaderFields)
		if l != 2 {
			return nil, fmt.Errorf("invalid secret key format")
		}
		if secretKeyHeaderFields[0] != string(header.Ed25519) {
			return nil, fmt.Errorf("unknown secret key type")
		}

		secretKeyString := secretKeyHeaderFields[1]

		if len(secretKeyString) != 103 {
			return nil, fmt.Errorf("invalid secret key length")
		}

		identity, err := dashi.NewIdentityFromSecretKeyString(secretKeyString)
		if err != nil {
			return nil, err
		}

		identities = append(identities, *identity)
	}

	return identities, nil
}

func openFile(name string) (*os.File, error) {
	var file *os.File

	if name == "-" {
		if stdinInUse {
			return nil, fmt.Errorf("standard input is used for multiple purposes")
		}
		stdinInUse = true
		file = os.Stdin
	} else {
		var err error
		file, err = os.Open(name)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %v", err)
		}
	}
	return file, nil
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

func stripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}
