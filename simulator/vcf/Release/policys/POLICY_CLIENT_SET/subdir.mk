O_SRCS += \
../policys/POLICY_CLIENT_SET/policy_client_set.o 

CPP_SRCS += \
../policys/POLICY_CLIENT_SET/policy_client_set.cpp 

OBJS += \
./policys/POLICY_CLIENT_SET/policy_client_set.o 

CPP_DEPS += \
./policys/POLICY_CLIENT_SET/policy_client_set.d 


# Each subdirectory must supply rules for building sources it contributes
policys/POLICY_CLIENT_SET/%.o: ../policys/POLICY_CLIENT_SET/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


