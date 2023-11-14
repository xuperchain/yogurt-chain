package xuperbeacon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"

	"github.com/xuperchain/yogurt-chain/geth/accounts"
	"github.com/xuperchain/yogurt-chain/geth/common/hexutil"
	"github.com/xuperchain/yogurt-chain/geth/common/lru"
	"github.com/xuperchain/yogurt-chain/geth/consensus/yogurt/xuper-beacon/pb"
	"github.com/xuperchain/yogurt-chain/geth/core/types"
	"github.com/xuperchain/yogurt-chain/geth/crypto"
	"github.com/xuperchain/yogurt-chain/geth/params"
	"google.golang.org/grpc"
)

var (
	extraVanity = 32                     // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal
)

type randomLRU = lru.Cache[uint64, *pb.QueryRandomNumberResponse] // beacon random cache, key: height, value: beacon response

// SignerFn hashes and signs the data to be signed by a backing account.
type SignerFn func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)

// 根据配置的信标链地址，通过高度查询对应随机数
// 同时配置中有公钥，可以验证随机数是否可信
type Beacon struct {
	config      *params.YogurtConfig
	randomCache *randomLRU // cache of beacon random number
	conn        *grpc.ClientConn
	client      pb.RandomClient
}

func NewBeacon(config *params.YogurtConfig) *Beacon {
	if config.BeaconURL != "" && config.BeaconPubKey != "" {
		conn, err := grpc.DialContext(context.Background(), config.BeaconURL, grpc.WithInsecure())
		if err != nil {
			fmt.Println("Failed to connect beacon gRPC:", err)
			return &Beacon{
				config: config,
			}
		}
		client := pb.NewRandomClient(conn)
		return &Beacon{config: config, randomCache: lru.NewCache[uint64, *pb.QueryRandomNumberResponse](128), conn: conn, client: client}
	}
	return &Beacon{
		config: config,
	}
}
func (b *Beacon) Close() {
	if b != nil && b.conn != nil {
		_ = b.conn.Close()
	}
}

// VerifyRandomNumber 验证 header 中的随机数是否可信，验证通过则返回随机数，验证失败则返回 nil
func (b *Beacon) VerifyHeaderExtra(header *types.Header, extraRandomLen, extraRandomSignLen int) (*big.Int, bool) {
	if !b.ConnectedBeacon() {
		rand.Seed(header.Number.Int64())
		r := rand.Int63n(header.Number.Int64())
		return big.NewInt(r), true
	}

	// header.Extra: extraVanity + extraRandomLen + extraRandomSignLen + {signers} + extraSeal
	// extraVanity        = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	// extraRandomLen     = 48
	// extraRandomSignLen = crypto.SignatureLength
	if len(header.Extra) > extraVanity+extraSeal {
		randomNumBytes := header.Extra[extraVanity : extraVanity+extraRandomLen]
		randomSignBytes := header.Extra[extraVanity+extraRandomLen : extraVanity+extraRandomLen+extraRandomSignLen]
		ok := crypto.VerifySignature(hexutil.MustDecode(b.config.BeaconPubKey),
			crypto.Keccak256([]byte(hex.EncodeToString(randomNumBytes))),
			randomSignBytes[:crypto.RecoveryIDOffset])

		if ok {
			return big.NewInt(0).SetBytes([]byte(randomNumBytes)), ok
		}
		return big.NewInt(0), false
	}
	return big.NewInt(0), false
}

func (b *Beacon) GetHeaderExtraRandomAndSign(height uint64, acc accounts.Account, sf func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)) ([]byte, error) {
	if !b.ConnectedBeacon() {
		return nil, nil
	}
	// 先查询缓存，没有则访问信标链，获取随机数，并验证是否可信
	var (
		resp *pb.QueryRandomNumberResponse
		err  error
		ok   bool
	)
	if resp, ok = b.randomCache.Get(height); !ok {
		resp, err = b.doQueryRandomNumAndVerify(height, acc, sf)
		if err != nil {
			return nil, err
		}
		b.randomCache.Add(height, resp)
	}

	rb, err := hex.DecodeString(resp.RandomNumber)
	if err != nil {
		return nil, err
	}
	extra := append(rb, resp.Sign...)
	return extra, nil
}

func (b *Beacon) GetRandomNumber(height uint64, acc accounts.Account, sf func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)) (*big.Int, error) {
	if !b.ConnectedBeacon() {
		rand.Seed(int64(height))
		r := rand.Int63n(int64(height))
		return big.NewInt(r), nil
	}

	var (
		resp *pb.QueryRandomNumberResponse
		err  error
		ok   bool
	)
	if resp, ok = b.randomCache.Get(height); !ok {
		resp, err = b.doQueryRandomNumAndVerify(height, acc, sf)
		if err != nil {
			return nil, err
		}
		b.randomCache.Add(height, resp)
	}

	rb, err := hex.DecodeString(resp.RandomNumber)
	if err != nil {
		return nil, err
	}
	return big.NewInt(0).SetBytes([]byte(rb)), nil
}

// doQueryRandomNumAndVerify 请求 beacon 链，并验证 header 中的随机数是否可信，sign 是当前节点对 height 的签名。
// 调用之前应该查询一下 cache 是否有想要的数据，没有再调用此接口。
func (b *Beacon) doQueryRandomNumAndVerify(height uint64, acc accounts.Account, sf func(signer accounts.Account, mimeType string, message []byte) ([]byte, error)) (*pb.QueryRandomNumberResponse, error) {
	if sf == nil {
		return nil, errors.New("signFn not ready, please wait a moment")
	}
	value, err := json.Marshal(height) // 采用 json 序列化后再签名，server 端验签也是 json 序列化
	if err != nil {
		return nil, err
	}

	sign, err := sf(acc, accounts.MimetypeClique, value)
	if err != nil {
		return nil, err
	}

	pubkey, err := crypto.SigToPub(crypto.Keccak256(value), sign)
	if err != nil {
		return nil, err
	}
	p := crypto.CompressPubkey(pubkey)

	request := &pb.QueryRandomNumberRequest{
		Height:        height,
		NodePublicKey: "0x" + hex.EncodeToString(p),
		Sign:          sign,
	}
	resp, err := b.client.QueryRandomNumber(context.Background(), request)
	if err != nil {
		return nil, err
	}

	if resp.ErrorCode != 0 {
		return nil, fmt.Errorf("QueryRandomNumber error: %v", resp.ErrorMessage)
	}

	message := resp.RandomNumber // current number
	// check sign for random number
	numberSign := resp.Sign
	serverPublicKey := b.config.BeaconPubKey
	signPass := crypto.VerifySignature(hexutil.MustDecode(serverPublicKey),
		crypto.Keccak256([]byte(message)),
		numberSign[:crypto.RecoveryIDOffset])
	if !signPass {
		return nil, errors.New("check beacon chain response sign failed")
	}
	return resp, nil
}

// ConnectedBeacon 是否真的连接到了信标链
func (b *Beacon) ConnectedBeacon() bool {
	return b.client != nil
}
