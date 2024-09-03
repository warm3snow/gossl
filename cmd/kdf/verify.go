package kdf

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/kdf/kdf_impl"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "verify a key derivation function output",
	Long:  `verify a key derivation function output against a password.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := verifyKdf(cmd); err != nil {
			panic(err)
		}
	},
}

func init() {
	kdfCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func verifyKdf(cmd *cobra.Command) error {
	var (
		verifyOk bool
		err      error
	)

	algo := cmd.Flag("algo").Value.String()
	in, err := cmd.Flags().GetString("in")
	if err != nil {
		return errors.Errorf("get in flag error: %v", err)
	}
	key, err := utils.ReadFile(in)
	if err != nil {
		return errors.Wrap(err, "read derive key from file failed")
	}
	deriveKey := string(key)

	password, err := cmd.Parent().Flags().GetString("password")
	if err != nil {
		return errors.Errorf("get password flag error: %v", err)
	}

	switch algo {
	case "scrypt":
		impl := &kdf_impl.ScryptImpl{}
		verifyOk, err = impl.VerifyDeriveKeyStr(deriveKey, []byte(password))
	case "argon2":
		impl := &kdf_impl.Argon2Impl{}
		verifyOk, err = impl.VerifyDeriveKeyStr(deriveKey, []byte(password))
	case "bcrypt":
		impl := &kdf_impl.BcryptImpl{}
		verifyOk, err = impl.VerifyDeriveKeyStr(deriveKey, []byte(password))
	case "pbkdf2":
		impl := &kdf_impl.Pbkdf2Impl{}
		verifyOk, err = impl.VerifyDeriveKeyStr(deriveKey, []byte(password))
	default:
		return errors.New("unsupported algorithm")
	}

	if err != nil {
		return errors.Wrap(err, "verify derive key failed")
	}
	if !verifyOk {
		return errors.New("invalid derive key against given password")
	}

	utils.Print(os.Stdout, []byte("verify derive key successfully"))
	return nil
}
