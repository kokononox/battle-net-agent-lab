/* Raw Ghidra 12.2 output; analyst-supplied function extent; no type/signature corrections.
   API completion is not proof of semantic correctness. Original PE bytes unchanged. */
/* RVA 2006630..200666d */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int review_dll_entry(undefined8 param_1,int param_2,longlong param_3)

{
  int iVar1;
  int iVar2;
  
  if (param_2 == 1) {
    review_cookie_initializer_candidate();
  }
  if ((param_2 == 0) && (_DAT_182194ca0 < 1)) {
    return 0;
  }
  if (param_2 - 1U < 2) {
    if (_DAT_182040ab0 == 0) {
      iVar2 = 1;
    }
    else {
      iVar2 = (*(code *)PTR__guard_dispatch_icall_18209f1d0)();
    }
    if (iVar2 == 0) {
      return 0;
    }
    iVar2 = FUN_1820064b8(param_1,param_2,param_3);
    if (iVar2 == 0) {
      return 0;
    }
  }
  iVar2 = review_application_body_unresolved(param_1,param_2,param_3);
  if ((param_2 == 1) && (iVar2 == 0)) {
    review_application_body_unresolved(param_1,0,param_3);
    FUN_182006438(param_3 != 0);
    if (_DAT_182040ab0 != 0) {
      (*(code *)PTR__guard_dispatch_icall_18209f1d0)(param_1,0,param_3);
    }
  }
  if ((param_2 == 0) || (param_2 == 3)) {
    iVar1 = FUN_1820064b8(param_1,param_2,param_3);
    iVar2 = 0;
    if (iVar1 != 0) {
      if (_DAT_182040ab0 == 0) {
        iVar2 = 1;
      }
      else {
        iVar2 = (*(code *)PTR__guard_dispatch_icall_18209f1d0)(param_1,param_2,param_3);
      }
    }
  }
  return iVar2;
}


