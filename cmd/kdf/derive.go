/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>

*/
package kdf

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/warm3snow/gossl/kdf"
	"github.com/warm3snow/gossl/kdf/kdf_impl"
	"github.com/warm3snow/gossl/utils"
	"os"
)

// deriveCmd represents the derive command
var deriveCmd = &cobra.Command{
	Use:   "derive",
	Short: "derive key from password using key derivation function",
	Long:  `derive key from password using key derivation function`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runDerive(cmd, args); err != nil {
			panic(err)
		}
	},
}

func init() {
	kdfCmd.AddCommand(deriveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deriveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// deriveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	deriveCmd.Flags().IntVar(&iterationNumber, "iter", 1000, "Specify the iteration number")
	deriveCmd.Flags().IntVar(&keyLen, "keylen", 32, "Specify the key length")
	deriveCmd.Flags().IntVar(&saltLen, "saltlen", 16, "Specify the salt length")

	deriveCmd.Flags().IntVar(&N, "N", 32768, "Specify the N parameter, only for scrypt")
	deriveCmd.Flags().IntVar(&R, "R", 8, "Specify the r parameter, only for scrypt")
	deriveCmd.Flags().IntVar(&P, "P", 1, "Specify the p parameter, only for scrypt")

	deriveCmd.Flags().IntVar(&time, "time", 1, "Specify the time parameter, only for argon2")
	deriveCmd.Flags().IntVar(&memory, "memory", 64*1024, "Specify the memory parameter, only for argon2")
	deriveCmd.Flags().IntVar(&threads, "threads", 4, "Specify the threads parameter, only for argon2")

	deriveCmd.Flags().IntVar(&cost, "cost", 10, "Specify the cost parameter, only for bcrypt")
}

var (
	iterationNumber int

	// Scrypt flags
	N, R, P int

	// Argon2 flags
	time, memory, threads int

	// Bcrypt flags
	cost int

	// common flags
	keyLen  int
	saltLen int
)

func runDerive(cmd *cobra.Command, args []string) error {
	algo, err := cmd.Flags().GetString("algo")
	if err != nil {
		return errors.Errorf("get algo flag error: %v", err)
	}

	password, err := cmd.Flags().GetString("password")
	if err != nil {
		return errors.Errorf("get password flag error: %v", err)
	}

	_, exist := kdf.AlgorithmMap[algo]
	if !exist {
		return errors.Errorf("unsupported kdf algorithm: %s", algo)
	}

	var (
		key string
	)
	switch algo {
	case "pbkdf2":
		impl := kdf_impl.NewPbkdf2Impl(iterationNumber, keyLen, saltLen)
		_, err = impl.DeriveKeyByPassword(password)
		key = impl.GetDeriveKeyStr()
	case "scrypt":
		impl := kdf_impl.NewScryptImpl(N, R, P, keyLen, saltLen)
		_, err = impl.DeriveKeyByPassword(password)
		key = impl.GetDeriveKeyStr()
	case "argon2":
		impl := kdf_impl.NewArgon2Impl(time, memory, threads, keyLen, saltLen)
		_, err = impl.DeriveKeyByPassword(password)
		key = impl.GetDeriveKeyStr()
	case "bcrypt":
		impl := kdf_impl.NewBcryptImpl(cost)
		_, err = impl.DeriveKeyByPassword(password)
		key = impl.GetDeriveKeyStr()
	default:
		return errors.Errorf("unsupported kdf algorithm: %s", algo)
	}

	if err != nil {
		return errors.Wrap(err, "derive key by password failed")
	}

	out := cmd.Flag("out").Value.String()
	if out != "" {
		if err := utils.WriteFile(out, []byte(key)); err != nil {
			return errors.Wrap(err, "write key to file failed")
		}
	} else {
		if err := utils.Print(os.Stdout, []byte(key)); err != nil {
			return errors.Wrap(err, "print key to stdout failed")
		}
	}

	return nil
}
