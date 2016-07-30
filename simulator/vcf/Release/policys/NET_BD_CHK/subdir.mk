################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/NET_BD_CHK/net_bd_chk.o 

CPP_SRCS += \
../policys/NET_BD_CHK/net_bd_chk.cpp 

OBJS += \
./policys/NET_BD_CHK/net_bd_chk.o

CPP_DEPS += \
./policys/NET_BD_CHK/net_bd_chk.d 


# Each subdirectory must supply rules for building sources it contributes
policys/NET_BD_CHK/%.o: ../policys/NET_BD_CHK/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


