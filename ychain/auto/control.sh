#!/bin/sh

cd `dirname $0`

Pwd=`pwd`
Self="control.sh"
AppName="xchain"
ClientName="xchain-cli"

RecommendShell="sh"
if [ -e /etc/os-release ]; then
    . /etc/os-release
    if [ "x$NAME" = "xUbuntu" ]; then
        # recommend bash in Ubuntu
        RecommendShell="bash"
    fi
fi
UsageArgs="{stop|start|restart|forcestop}"
Usage="$RecommendShell ./$Self $UsageArgs"

# 默认启动环境
LogDir="$Pwd/logs"
ControlLogPath="$LogDir/control.log"
TmpDir="$Pwd/tmp"
AppPidFile="$TmpDir/$AppName.pid"
ConfDir="$Pwd/conf"
AppConf="env.yaml"
RootChainDir="$Pwd/data/blockchain/xuper"

export PATH="$Pwd/bin":$PATH

# check param
[ -f "$ConfDir/$AppConf" ] || { echo "env.yaml not exist!"; exit 1; }

if [ "$0" != "./$Self" ] && [ "$0" != "$Self" ]; then
    echo "Exec dir error. $0 Example:$Usage"
    exit 1
fi


# file check
BinPath="$Pwd/bin/$AppName"
ClientPath="$Pwd/bin/$ClientName"
ConfPath="$ConfDir/$AppConf"
[ -f "$BinPath" ] || { echo "app bin not exist!"; exit; }
[ -f "$ClientPath" ] || { echo "client bin not exist!"; exit; }
[ -f "$ConfPath" ] || { echo "config not exist!"; exit; }
echo $BinPath
echo $ConfPath

ulimit -c 0

start() {
    pid=$(getpid)
    if [ -n "$pid" ]; then
        echo "process exist, app is running? pid:$pid"
        exit 1
    fi

    if [ ! -d "$RootChainDir" ]; then
        $BinPath createChain
        if [ $? -ne 0 ]; then
            echo "create root chain failed!"
            exit 1
        fi
    fi

    if [ ! -d "$LogDir" ];then
        mkdir "$LogDir"
    fi

    if [ ! -d "$TmpDir" ];then
        mkdir "$TmpDir"
    fi

    cmd="nohup $BinPath startup --conf $ConfPath >/dev/null 2>$LogDir/nohup.out &"
    echo "start $AppName. cmd:$cmd"

    # foreground running for docker runtime and foreground log
    if [ 1"$1"  = 1"-f" ];then
      $BinPath startup --conf $ConfPath
      exit $?
    fi

    nohup $BinPath startup --conf $ConfPath >/dev/null 2>"$LogDir/nohup.out" &

    # 检查确保正常启动运行
    waitRun
    if [ "$?" != "0" ]; then
        echo "start timeout,force stop app."
        forcestop
        echo "start fail."
        exit 1
    fi

    pid=$(getpid)
    echo "$pid" > "$AppPidFile"
    echo "start finish.pid:$pid"
}

forcestop() {
    echo "force stop $AppName."
    killProc -9
    if [ "$?" != "0" ]; then
        echo "force stop failed"
        exit 1
    fi

    echo "force stop succ"
}

stop() {
    echo "stop $AppName."
    killProc -15
    if [ "$?" != "0" ]; then
        echo "stop failed"
        exit 1
    fi

    echo "stop succ"
}

killProc() {
    signal=$1

    pid=$(getpid)
    if [ -n "$pid" ]; then
        echo "$BinPath"
        echo "kill $signal $pid"
        kill "$signal" "$pid"

        # 等待进程退出
        waitExit "$pid" "$BinPath"
        if [ "$?" != "0" ]; then
            echo "proc stop timeout,exit.pid:$pid bin:$BinPath"
            exit 1
        fi
    fi

    if [ -f "$AppPidFile" ];then
        rm "$AppPidFile"
    fi
}

procIsRun() {
    pid1=$(getpid)
    if [ -z "$pid1" ]; then
        return 1
    fi

    # 进程可能出现短暂起来又退出的情况，检查两次确保进行稳定运行
    sleep 3s

    pid2=$(getpid)
    if [ "$pid1" = "$pid2" ]; then
        return 0
    fi

    return 1
}

getpid() {
    pid=`ps -ef | grep "$BinPath" | grep -v grep | awk -F' ' '{print $2}'`
    if [ -z "$pid" ]; then
        echo ""
        return
    fi
    echo "$pid"
}

waitRun() {
    for i in $(seq 10);
    do
        echo -n "."
        procIsRun
        if [ "$?" = "0" ]; then
            echo "start proc succ."
            return 0
        fi
        sleep 1s
    done

    echo "start timeout"
    return 1
}

waitExit() {
    pid=$1
    bin=$2
    if [ -z "$pid" ]; then
        echo "pid is empty!"
        return 1
    fi

    if [ -z "$bin" ]; then
        echo "bin name is empty!"
        return 1
    fi

    for i in $(seq 60);
    do
        echo -n "."
        p=`ps -ef | grep "$pid" | grep "$bin" | grep -v grep | awk -F' ' '{print $2}'`
        if [ -z "$p" ]; then
            echo "exit finish!"
            return 0
        fi
        sleep 1s
    done

    echo "exit timeout!"
    return 1
}

case "$1" in
    start)
        start $2
        echo "Done!"
        ;;
    stop)
        stop
        echo "Done!"
        ;;
    forcestop)
        forcestop
        echo "Done!"
        ;;
    restart)
        stop
        sleep 1s
        start
        echo "Done!"
        ;;
    *)
        echo "$Usage"
        ;;
esac

