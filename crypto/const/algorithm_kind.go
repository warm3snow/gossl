/**
 * @Author: xueyanghan
 * @File: algorithm_kind.go
 * @Version: 1.0.0
 * @Description: desc.
 * @Date: 2024/9/24 15:21
 */

package _const

type AlgorithmKind string

func (a AlgorithmKind) String() string {
	return string(a)
}

const (
	Symmetric      AlgorithmKind = "symmetric"
	Digest         AlgorithmKind = "digest"
	Asymmetric     AlgorithmKind = "asymmetric"
	X509Kind       AlgorithmKind = "encode"
	CommitmentKind AlgorithmKind = "commitment"
)
