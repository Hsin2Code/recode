#! /bin/bash
function usage() {
    echo "Usage:./clt_simulator.sh [run|stop|usage|clean|count|error] Dev_ID Server_IP Client_IP Report_INV Report_Times Pull_Policy_INV Clt_NUM RUM_TIME REPORT_ASSERT RANDOM_MAX"
}

function stop() {
    pkill --signal SIGINT client
}
case $1 in
    (stop)
	stop
	exit 1
	;;
    (usage)
	usage
	exit 1
	;;
    (clean)
    rm -rf ./logs/*; rm -rf ./reports/*;
    exit 1
    ;;
    (count)
    echo "send_success_sum: " `cat ./reports/* | grep send_success | awk -F '= ' '{ print $2}' | awk '{s+=$1} END {print s}'`
    exit 1
    ;;
    (error)
     ls -lah ./logs/* | grep error | awk '$5 > 0 {print "file: " $NF}'
    exit 1
    ;;
esac

if [ $# -lt 8 ]; then
    usage
    exit 1
fi

Devid=$2
Serip=$3
Cltip=$4
Invpush=$5
Times=$6
Invpull=$7
Num=$8
Run_time=$9
Report_assert=${10}
Random_max=${11}

a=`echo $Cltip|awk -F . '{print $1}'`  #以"."分隔，取出每个列的值
b=`echo $Cltip|awk -F . '{print $2}'`
c=`echo $Cltip|awk -F . '{print $3}'`
d=`echo $Cltip|awk -F . '{print $4}'`

folder=./run_log
if [ ! -d "$folder" ]; then
    mkdir ./run_log
fi


function run() {
    min=1
    old_group=0
    _random_group_sec=0
    frist=0
    while [ $min -le $Num ]
    do
        last_count=`expr $(($min/$Random_max))`
        if [ $last_count -ne $old_group ]; then
            _random_group_sec=$((RANDOM%5+1))
            old_group=$last_count
            if [ $frist -ne 0 ]; then
                while true; do
                    already_report=`cat ./logs/simulator.log| grep report | wc -l`
                    ac_min=$(($min-1))
                    if [ $already_report -lt $ac_min ]; then
                        sleep 1
                        echo "wait report sucess number: "$already_report "should have: " $ac_min
                    else
                        break
                    fi
                done
            fi
            frist=1
        fi

        nohup ./client_simulator -d $Devid$min -p $Serip -s $a.$b.$c.$d -l $Invpush -m $Invpull -T $Times -t $Run_time -M $Report_assert -R $_random_group_sec >> ./run_log/$min.file 2>&1 &
        echo "PID = $!" > ./run_log/$min.file
        echo "Start a client: Dev_id=$Devid$min Ser_ip=$Serip Clt_ip=$a.$b.$c.$d PID=$! RANDOM_START: $_random_group_sec"
        min=$(($min+1))
        d=$(($d+1))
        if [ $d -gt 254 ]; then
            c=$(($c+1))
            d=1
        fi



    done
}
case $1 in
    (run)
	run
	;;
    (*)
	usage
	;;
esac

