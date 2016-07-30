################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/HTTP_VISITED_CTRL/http_visit_ctrl.o 

CPP_SRCS += \
../policys/HTTP_VISITED_CTRL/http_visit_ctrl.cpp 

OBJS += \
./policys/HTTP_VISITED_CTRL/http_visit_ctrl.o 

CPP_DEPS += \
./policys/HTTP_VISITED_CTRL/http_visit_ctrl.d 

PCAP_INC = -I../include/pcap-1.0/


# Each subdirectory must supply rules for building sources it contributes
policys/HTTP_VISITED_CTRL/%.o: ../policys/HTTP_VISITED_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall $(PCAP_INC) -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


