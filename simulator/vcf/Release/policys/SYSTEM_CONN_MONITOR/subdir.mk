################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../policys/SYSTEM_CONN_MONITOR/sys_conn_monitor.cpp 

C_SRCS += \
../policys/SYSTEM_CONN_MONITOR/iftable.c \
../policys/SYSTEM_CONN_MONITOR/libnetfilter_queue.c \
../policys/SYSTEM_CONN_MONITOR/libnfnetlink.c \
../policys/SYSTEM_CONN_MONITOR/rtnl.c 

OBJS += \
./policys/SYSTEM_CONN_MONITOR/iftable.o \
./policys/SYSTEM_CONN_MONITOR/libnetfilter_queue.o \
./policys/SYSTEM_CONN_MONITOR/libnfnetlink.o \
./policys/SYSTEM_CONN_MONITOR/rtnl.o \
./policys/SYSTEM_CONN_MONITOR/sys_conn_monitor.o 

C_DEPS += \
./policys/SYSTEM_CONN_MONITOR/iftable.d \
./policys/SYSTEM_CONN_MONITOR/libnetfilter_queue.d \
./policys/SYSTEM_CONN_MONITOR/libnfnetlink.d \
./policys/SYSTEM_CONN_MONITOR/rtnl.d 

CPP_DEPS += \
./policys/SYSTEM_CONN_MONITOR/sys_conn_monitor.d 

PCAP_INC = -I../include/pcap-1.0/

# Each subdirectory must supply rules for building sources it contributes
policys/SYSTEM_CONN_MONITOR/%.o: ../policys/SYSTEM_CONN_MONITOR/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O3 -Wall -c $(PCAP_INC) \
		-fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

policys/SYSTEM_CONN_MONITOR/%.o: ../policys/SYSTEM_CONN_MONITOR/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c $(PCAP_INC) \
		-fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


