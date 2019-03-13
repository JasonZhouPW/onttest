package main

import "fmt"

import (
	"bytes"
	"encoding/hex"
	"github.com/ontio/ontology-crypto/keypair"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/config"
	"github.com/ontio/ontology/common/log"
	"github.com/ontio/ontology/core/genesis"
	"github.com/ontio/ontology/core/ledger"
	"github.com/ontio/ontology/core/payload"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/events"
	"os"
	"runtime"

	"encoding/binary"
	"github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology/common/constants"
	"github.com/ontio/ontology/common/serialization"
	"github.com/ontio/ontology/smartcontract/states"
	"io/ioutil"
	"time"
)

const (
	DefaultMultiCoreNum = 4
)

func init() {
	log.Init(log.PATH, log.Stdout)
	runtime.GOMAXPROCS(4)
}

var blockBuf *bytes.Buffer

func main() {
	datadir := "testdata"
	_ = os.RemoveAll(datadir)
	log.Trace("Node version: ", config.Version)

	sdk := ontology_go_sdk.NewOntologySdk()

	acct := account.NewAccount("")
	buf := keypair.SerializePublicKey(acct.PublicKey)
	config.DefConfig.Genesis.ConsensusType = "solo"
	config.DefConfig.Genesis.SOLO.GenBlockTime = 3
	config.DefConfig.Genesis.SOLO.Bookkeepers = []string{hex.EncodeToString(buf)}
	log.Debug("The Node's PublicKey ", acct.PublicKey)

	bookkeepers := []keypair.PublicKey{acct.PublicKey}
	//Init event hub
	events.Init()

	log.Info("1. Loading the Ledger")
	var err error
	ledger.DefLedger, err = ledger.NewLedger(datadir, 100000000)
	if err != nil {
		log.Fatalf("NewLedger error %s", err)
		os.Exit(1)
	}
	genblock, err := genesis.BuildGenesisBlock(bookkeepers, config.DefConfig.Genesis)
	if err != nil {
		log.Error(err)
		return
	}
	err = ledger.DefLedger.Init(bookkeepers, genblock)
	if err != nil {
		log.Fatalf("DefLedger.Init error %s", err)
		os.Exit(1)
	}

	//deploy wasmcontract
	log.Info("2. Deploy wasm contract")
	testFile := "./rustOEP4.wasm"
	code, err := ioutil.ReadFile(testFile)
	if err != nil {
		fmt.Printf("open wasmfile error:%s\n", err.Error())
		return
	}
	tx := NewDeployWasmVMTx(code)
	dptx, err := tx.IntoImmutable()
	if err != nil {
		fmt.Printf("IntoImmutable error:%s\n", err.Error())
		return
	}
	codeHash := common.ToHexString(code)
	contractAddr, err := utils.GetContractAddress(codeHash)
	if err != nil {
		fmt.Printf("GetContractAddress error:%s\n", err.Error())
		return
	}

	wallet, err := GetWallet()
	if err != nil {
		fmt.Printf("getWallet error:%s\n", err.Error())
		return
	}
	acct1, err := wallet.GetDefaultAccount([]byte("123456"))
	if err != nil {
		fmt.Printf("GetDefaultAccount error:%s\n", err.Error())
		return
	}
	signer := &account.Account{PrivateKey: acct1.PrivateKey,
		PublicKey: acct1.PublicKey,
		Address:   acct1.Address,
		SigScheme: acct1.SigScheme}

	err = signTransaction(signer, tx)
	if err != nil {
		fmt.Printf("signTransaction error:%s\n", err.Error())
		return
	}

	dpblk, err := makeBlock(acct, []*types.Transaction{dptx})

	err = ledger.DefLedger.AddBlock(dpblk, common.UINT256_EMPTY)
	if err != nil {
		fmt.Println("persist block error", err)
		return
	}

	//invoke init()
	log.Info("3. invoke oep4 init method")

	tx, err = NewWasmInvokeTx(contractAddr, "initialize", []interface{}{signer.Address}, sdk)
	if err != nil {
		fmt.Println("NewWasmInvokeTx error", err)
		return
	}
	fmt.Printf("txtype is %x\n",tx.TxType)
	err = signTransaction(signer, tx)
	if err != nil {
		fmt.Printf("signTransaction error:%s\n", err.Error())
		return
	}
	inittx,_ := tx.IntoImmutable()
	blk, err := makeBlock(acct, []*types.Transaction{inittx})

	err = ledger.DefLedger.AddBlock(blk, common.UINT256_EMPTY)
	if err != nil {
		fmt.Println("persist block error", err)
		return
	}

	toacct := account.NewAccount("")
	fmt.Printf("to acct address is %s\n", toacct.Address.ToBase58())
	TxTest(acct, signer, toacct, contractAddr, sdk)

}

func NewDeployWasmVMTx(contractCode []byte) *types.MutableTransaction {
	deployPayload := &payload.DeployCode{
		Code:        contractCode,
		VmType:      byte(3),
		Name:        "test",
		Version:     "1.0",
		Author:      "test",
		Email:       "test",
		Description: "test",
	}
	tx := &types.MutableTransaction{
		Version:  sdkcom.VERSION_TRANSACTION,
		TxType:   types.Deploy,
		Nonce:    uint32(time.Now().Unix()),
		Payload:  deployPayload,
		GasPrice: 0,
		GasLimit: 20000000,
		Sigs:     make([]types.Sig, 0, 0),
	}
	return tx
}

func NewWasmInvokeTx(contractAddress common.Address, method string, params []interface{}, sdk *ontology_go_sdk.OntologySdk) (*types.MutableTransaction, error) {
	contract := &states.WasmContractParam{}
	contract.Address = contractAddress
	argbytes, err := buildWasmContractParam(method, params)
	if err != nil {
		return nil, fmt.Errorf("buildWasmContractParam error:%s\n", err.Error())
	}
	contract.Args = argbytes
	sink := common.NewZeroCopySink(nil)
	contract.Serialization(sink)
	tx := sdk.NewInvokeWasmTransaction(0, 20000000, sink.Bytes())
	return tx, nil
}

//for wasm vm
//build param bytes for wasm contract
func buildWasmContractParam(method string, params []interface{}) ([]byte, error) {
	bf := bytes.NewBuffer(nil)
	serialization.WriteString(bf, method)
	for _, param := range params {
		switch param.(type) {
		case string:
			tmp := bytes.NewBuffer(nil)
			serialization.WriteString(tmp, param.(string))
			bf.Write(tmp.Bytes())
		case int:
			tmpBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(tmpBytes, uint32(param.(int)))
			bf.Write(tmpBytes)
		case int64:
			tmpBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(tmpBytes, uint64(param.(int64)))
			bf.Write(tmpBytes)
		case uint16:
			tmpBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(tmpBytes, param.(uint16))
			bf.Write(tmpBytes)
		case uint32:
			tmpBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(tmpBytes, param.(uint32))
			bf.Write(tmpBytes)
		case uint64:
			tmpBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(tmpBytes, param.(uint64))
			bf.Write(tmpBytes)
		case []byte:
			tmp := bytes.NewBuffer(nil)
			serialization.WriteVarBytes(tmp, param.([]byte))
			bf.Write(tmp.Bytes())
		case common.Uint256:
			bs := param.(common.Uint256)
			parambytes := bs[:]
			bf.Write(parambytes)
		case common.Address:
			bs := param.(common.Address)
			parambytes := bs[:]
			bf.Write(parambytes)
		case byte:
			bf.WriteByte(param.(byte))

		default:
			return nil, fmt.Errorf("not a supported type :%v\n", param)
		}
	}
	return bf.Bytes(), nil

}

func GetWallet() (*ontology_go_sdk.Wallet, error) {
	return ontology_go_sdk.OpenWallet("./wallet.dat")
}

func TxTest(issuer *account.Account, signer *account.Account, toacct *account.Account, contractAddress common.Address, sdk *ontology_go_sdk.OntologySdk) {

	from := signer.Address
	to := toacct.Address
	amountbs := make([]byte, 16)

	binary.LittleEndian.PutUint64(amountbs, uint64(1))
	parambs := make([]byte, 32)
	copy(parambs[:16], amountbs)

	amount, _ := common.Uint256ParseFromBytes(parambs)

	params := []interface{}{from, to, amount}
	loopcnt := 100000

	txs := make([]*types.Transaction, loopcnt)
	start := time.Now().UnixNano()
	for i := 0; i < loopcnt; i++ {
		tx, err := NewWasmInvokeTx(contractAddress, "transfer", params, sdk)
		if err != nil {
			fmt.Printf("NewWasmInvokeTx error :%s\n", err.Error())
			return
		}
		err = signTransaction(signer, tx)
		if err != nil {
			fmt.Printf("signTransaction error :%s\n", err.Error())
			return
		}
		txs[i], err = tx.IntoImmutable()
		if err != nil {
			fmt.Printf("signTransaction error :%s\n", err.Error())
			return
		}
	}
	fmt.Printf("make transfer:%d, cost:%d ns\n",loopcnt,time.Now().UnixNano() - start)

	signerbalance := getOEP4Balance(contractAddress, signer.Address)
	toacctBalance := getOEP4Balance(contractAddress, toacct.Address)
	fmt.Printf("before test signerbalance :%d\n, toacctBalance:%d\n", signerbalance, toacctBalance)

	txPerBlock := 5000
	start =time.Now().UnixNano()
	for j := 0; j < loopcnt/txPerBlock; j++ {
		blk, err := makeBlock(issuer, txs[j*txPerBlock:(j+1)*txPerBlock])
		if err != nil {
			fmt.Printf("makeBlock error :%s\n", err.Error())
			return
		}
		err = ledger.DefLedger.AddBlock(blk, common.UINT256_EMPTY)
		if err != nil {
			fmt.Println("persist block error", err)
			return
		}
	}
	fmt.Printf("exec transfer:%d, cost:%d ns\n",loopcnt,time.Now().UnixNano() - start)

	fmt.Println("done")
	signerbalance = getOEP4Balance(contractAddress, signer.Address)
	toacctBalance = getOEP4Balance(contractAddress, toacct.Address)
	fmt.Printf("after test signerbalance :%d\n, toacctBalance:%d\n", signerbalance, toacctBalance)

}

func signTransaction(signer *account.Account, tx *types.MutableTransaction) error {
	hash := tx.Hash()
	sign, _ := signature.Sign(signer, hash[:])
	tx.Sigs = append(tx.Sigs, types.Sig{
		PubKeys: []keypair.PublicKey{signer.PublicKey},
		M:       1,
		SigData: [][]byte{sign},
	})
	return nil
}

func checkEq(a, b uint64) {
	if a != b {
		panic(fmt.Sprintf("not equal. a %d, b %d", a, b))
	}
}

func getOEP4Balance(contractaddr common.Address, addr common.Address) uint64 {
	key := bytes.NewBuffer([]byte("b"))
	key.Write(addr[:])

	fmt.Printf("getOEP4Balance key is %v\n",key.Bytes())


	balanceBytes, _ := ledger.DefLedger.GetStorageData(contractaddr, key.Bytes())
	fmt.Printf("balanceBytes :%v\n", balanceBytes)
	balanceU256, err := common.Uint256ParseFromBytes(balanceBytes)
	if err != nil {
		fmt.Printf("error is %s\n", err.Error())
	}
	balance := binary.LittleEndian.Uint64(balanceU256[:8])
	return balance

}


func makeBlock(acc *account.Account, txs []*types.Transaction) (*types.Block, error) {
	nextBookkeeper, err := types.AddressFromBookkeepers([]keypair.PublicKey{acc.PublicKey})
	if err != nil {
		return nil, fmt.Errorf("GetBookkeeperAddress error:%s", err)
	}
	prevHash := ledger.DefLedger.GetCurrentBlockHash()
	height := ledger.DefLedger.GetCurrentBlockHeight()

	nonce := uint64(height)
	txHash := []common.Uint256{}
	for _, t := range txs {
		txHash = append(txHash, t.Hash())
	}

	txRoot := common.ComputeMerkleRoot(txHash)
	if err != nil {
		return nil, fmt.Errorf("ComputeRoot error:%s", err)
	}
	param := []common.Uint256{txRoot}

	blockRoot := ledger.DefLedger.GetBlockRootWithNewTxRoots(height+1, param)
	header := &types.Header{
		Version:          0,
		PrevBlockHash:    prevHash,
		TransactionsRoot: txRoot,
		BlockRoot:        blockRoot,
		Timestamp:        constants.GENESIS_BLOCK_TIMESTAMP + height + 1,
		Height:           height + 1,
		ConsensusData:    nonce,
		NextBookkeeper:   nextBookkeeper,
	}
	block := &types.Block{
		Header:       header,
		Transactions: txs,
	}

	blockHash := block.Hash()

	sig, err := signature.Sign(acc, blockHash[:])
	if err != nil {
		return nil, fmt.Errorf("[Signature],Sign error:%s.", err)
	}

	block.Header.Bookkeepers = []keypair.PublicKey{acc.PublicKey}
	block.Header.SigData = [][]byte{sig}
	return block, nil
}
