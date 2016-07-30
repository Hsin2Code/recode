#ifndef POLICY_CLIENT_SET_EDP_XXX
#define POLICY_CLIENT_SET_EDP_XXX

#include "../policysExport.h"
extern bool  policy_client_set_init();
extern bool  policy_client_set_worker(CPolicy * pPolicy, void * pParam);
extern void  policy_client_set_uninit();



class  PolicyClientSet : public CPolicy {
public :
	PolicyClientSet() {
		enPolicytype  type = POLICY_CLIENT_SET ;
		set_type(type);
	}
	~PolicyClientSet() {

	}
public:
	virtual  bool   import_xml(const char * pxml);
	virtual  void   copy_to(CPolicy * pDest) ;
private:
	property_def(sync_time, int);
};
#endif
