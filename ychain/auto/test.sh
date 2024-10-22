#!/bin/bash
set -x
#-------------------------------
# 自动测试功能点：
#    1.搭建网络环境
#    2.转账
#    3.合约
#    4.权限
#------------------------------

# 脚本绝对路径
AbsPath=$(cd $(dirname "$BASH_SOURCE"); pwd)
# 根路径
WorkRoot=$AbsPath/..
# 测试网络路径
TestNet=$WorkRoot/testnet
# 工作路径：所有命令在node1路径下运行
WorkPath=$TestNet/node1
# log
LogPath="${WorkPath}/logs"
ErrorLogFile="${LogPath}/xchain.log.wf"

# Make `alias` work in GitHub actions
alias xchain-cli='$WorkPath/bin/xchain-cli'
alias log_info='echo INFO $(date +"%Y-%m-%d %H:%M:%S") ${BASH_SOURCE##*/}:$LINENO'
alias log_error='echo ERROR $(date +"%Y-%m-%d %H:%M:%S") ${BASH_SOURCE##*/}:$LINENO'

contract_account_1=XC1111111111111111@xuper
contract_account_2=XC2222222222222222@xuper
contract_account_utxo_number=3333333333333333
contract_account_utxo="XC${contract_account_utxo_number}@xuper"

# testnet
function testnet() {
  # install
  source $WorkRoot/auto/deploy_testnet.sh || exit

  # start node
  (cd "$TestNet/node1" && bash control.sh start) &
  (cd "$TestNet/node2" && bash control.sh start) &
  (cd "$TestNet/node3" && bash control.sh start)
  wait

  cd "$WorkPath" || exit

  log_info "start testnet path=$(pwd)"

  # check status
  for i in $(seq 10);
  do
    sleep 3
    if ./bin/xchain-cli status ; then
      log_info "testnet started"
      return 0
    fi
  done

  log_error "start testnet failed"
  exit
}

# account
function account() {
  ## 账户
  ./bin/xchain-cli account newkeys --output data/alice || exit
  ./bin/xchain-cli transfer --to "$(cat data/alice/address)" --amount 10000000 || exit
  balance=$(./bin/xchain-cli account balance --keys data/alice)
  log_info "account $(cat data/alice/address) balance $balance"

  ## 合约账户
  ./bin/xchain-cli account new --account 1111111111111111 --fee 1000 || exit
  ./bin/xchain-cli transfer --to XC1111111111111111@xuper --amount 100000001 || exit
  balance=$(./bin/xchain-cli account balance XC1111111111111111@xuper)
  log_info "account XC1111111111111111@xuper balance $balance"

  ## 合约账户：desc 文件
  ./bin/xchain-cli account new --desc $WorkRoot/data/desc/NewAccount.json --fee 1000 || exit
  ./bin/xchain-cli transfer --to XC2222222222222222@xuper --amount 100000002 || exit
  balance=$(./bin/xchain-cli account balance XC2222222222222222@xuper)
  log_info "account XC2222222222222222@xuper balance $balance"
}

# contract
function contract() {
  cp $WorkRoot/auto/counter.wasm $WorkPath
  # wasm
  log_info "contract wasm"
  ./bin/xchain-cli wasm deploy $WorkPath/counter.wasm --cname counter.wasm \
            --account XC1111111111111111@xuper \
            --runtime c -a '{"creator": "xuper"}' --fee 155537 || {
              tail "${ErrorLogFile}"
              exit
            }
  log_info "contract wasm invoke"
  ./bin/xchain-cli wasm invoke --method increase -a '{"key":"test"}' counter.wasm --fee 100
  ./bin/xchain-cli wasm query --method get -a '{"key":"test"}' counter.wasm

  # 查询用户部署的合约
  log_info "contract XC1111111111111111@xuper"
  ./bin/xchain-cli account contracts --account XC1111111111111111@xuper
  log_info "contract $(cat data/keys/address)"
  ./bin/xchain-cli account contracts --address $(cat data/keys/address)
}

# 内置合约
function builtin() {
      # reserved_contracts
  log_info "contract reserved unified_check"
  ./bin/xchain-cli wasm deploy $WorkPath/build/unified_check --cname unified_check \
            --account XC1111111111111111@xuper \
            --runtime c -a '{"creator": "TeyyPLpp9L7QAcxHangtcHTu7HUZ6iydY"}' --fee 164735 || exit
  ./bin/xchain-cli wasm invoke unified_check --method register_aks \
            -a '{"aks":"SmJG3rH2ZzYQ9ojxhbRCPwFiE9y6pD1Co,iYjtLcW6SVCiousAb5DFKWtWroahhEj4u"}' --fee 155 || exit

  # forbidden_contract
  log_info "contract forbidden"
  ./bin/xchain-cli wasm deploy $WorkPath/build/forbidden --cname forbidden \
            --account XC1111111111111111@xuper \
            --runtime c -a '{"creator": "TeyyPLpp9L7QAcxHangtcHTu7HUZ6iydY"}' --fee 155679 || exit
  sleep 3s
}

function acl() {
  # acl addr
  mkdir -p data/acl

  # 设置合约账户acl
  log_info "acl account"
  echo "XC1111111111111111@xuper/$(cat $TestNet/node1/data/keys/address)" > data/acl/addrs
  ./bin/xchain-cli acl query --account XC1111111111111111@xuper
  ./bin/xchain-cli multisig gen --desc $WorkRoot/data/desc/SetAccountACL.json --fee 100
  ./bin/xchain-cli multisig sign --output sign.out
  ./bin/xchain-cli multisig send sign.out sign.out --tx tx.out || exit
  sleep 2s
  ./bin/xchain-cli acl query --account XC1111111111111111@xuper

  # 设置合约方法acl
  log_info "acl contract method"
  echo "XC1111111111111111@xuper/$(cat $TestNet/node2/data/keys/address)" >> data/acl/addrs
  ./bin/xchain-cli multisig gen --desc $WorkRoot/data/desc/SetMethodACL.json --fee 100
  ./bin/xchain-cli multisig sign --keys $TestNet/node1/data/keys --output sign1.out
  ./bin/xchain-cli multisig sign --keys $TestNet/node2/data/keys --output sign2.out
  ./bin/xchain-cli multisig send sign1.out,sign2.out sign1.out,sign2.out --tx tx.out  || exit
  sleep 2s
  ./bin/xchain-cli acl query --contract counter.wasm --method increase

  # 调用合约方法
  log_info "acl invoke contract method"
  ./bin/xchain-cli transfer --to "$(cat $TestNet/node2/data/keys/address)" --amount 10000000 || exit
  ./bin/xchain-cli transfer --to "$(cat $TestNet/node3/data/keys/address)" --amount 10000000 || exit
  ./bin/xchain-cli wasm invoke --method increase -a '{"key":"test"}' counter.wasm --fee 100 --keys $TestNet/node1/data/keys || exit
  ./bin/xchain-cli wasm invoke --method increase -a '{"key":"test"}' counter.wasm --fee 100 --keys $TestNet/node2/data/keys || exit
  # node3节点无权限，应该调用失败
  log_info "acl node3 invoke contract method: should 'ACL not enough'"
  ./bin/xchain-cli wasm invoke --method increase -a '{"key":"test"}' counter.wasm --fee 100 --keys $TestNet/node3/data/keys && exit
}

function height() {
  height1=$(./bin/xchain-cli status -H:37101 | grep trunkHeight | awk '{print $2}')
  height2=$(./bin/xchain-cli status -H:37102 | grep trunkHeight | awk '{print $2}')
  height3=$(./bin/xchain-cli status -H:37103 | grep trunkHeight | awk '{print $2}')

  log_info "height1=$height1 height2=$height2 height3=$height3"
  diff=$((2*height1-height2-height3))
  if [ $diff -gt 3 ]; then
		log_error "height inconsistency: height1=$height1 height2=$height2 height3=$height3" && exit
	fi
}

function clean() {
  num=$(ps -ef | grep "xuperchain/testnet" | grep -v grep | wc -l)
  if [ $num -gt 0 ]; then
    ps -ef | grep "xuperchain/testnet" | grep -v grep | awk '{print $2}' | xargs kill -9
  fi

  [ -d "$TestNet" ] && rm -rf "$TestNet"
}

function utxo() {

  xchain-cli account new --account ${contract_account_utxo_number} --fee 1000 --keys $TestNet/node3/data/keys
  xchain-cli account balance ${contract_account_utxo} --keys $TestNet/node3/data/keys
  xchain-cli transfer --to ${contract_account_utxo} --amount 10000 --keys $TestNet/node3/data/keys

  # test list
  xchain-cli utxo list -N 2 -A ${contract_account_utxo} | extract utxoCount
}

function extract() {
  key=$1
  while read -r line; do
    value=$(grep $key | awk '{print $2}')
    if [ -n "${value}" ]; then
      echo "${value}"
      return 0
    fi
  done

  return 1
}

function main() {
  xchain-cli status -H:37101
  height1=$(xchain-cli status -H:37101 | extract trunkHeight )
  echo height
}

case X$1 in
    Xclean)
        clean
        ;;
    Xtestnet)
        testnet
        ;;
    Xaccount)
        account
        ;;
    Xcontract)
        contract
        #builtin
        ;;
    Xacl)
        acl
        ;;
    Xheight)
        height
        ;;
    Xutxo)
        utxo
        ;;
    X*)
        main "$@"
esac
