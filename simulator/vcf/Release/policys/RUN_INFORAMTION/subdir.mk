################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/RUN_INFORAMTION/run_inforamtion.o 

CPP_SRCS += \
../policys/RUN_INFORAMTION/run_inforamtion.cpp 

OBJS += \
./policys/RUN_INFORAMTION/run_inforamtion.o 

CPP_DEPS += \
./policys/RUN_INFORAMTION/run_inforamtion.d 


# Each subdirectory must supply rules for building sources it contributes
policys/RUN_INFORAMTION/%.o: ../policys/RUN_INFORAMTION/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


