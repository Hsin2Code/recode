# for include all make and submake
COMPAT_INC:=-I../
MSGPACK_INC:=-I../../include/msgpack-c
PCAP_INC:= -I../include/pcap-1.0/
COMMON_INC:=-I../common/
GLOBAL_INC:= -I../../include
LIBS_INC:=-I../include
VRV_PROTOCOL:=-I../vrvprotocol
POLICY_EXPORT_INC:=-I../policys

INC_FLAGS:= $(PCAP_INC) $(COMMON_INC) $(GLOBAL_INC) \
	 $(LIBS_INC) $(VRV_PROTOCOL) $(POLICY_EXPORT_INC) \
	  $(MSGPACK_INC) 

CC=g++
