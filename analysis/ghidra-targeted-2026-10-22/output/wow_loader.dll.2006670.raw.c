/* Raw Ghidra 12.2 output; analyst-supplied function extent; no type/signature corrections.
   API completion is not proof of semantic correctness. Original PE bytes unchanged. */
/* RVA 2006670..200671c */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void review_cookie_initializer_candidate(void)

{
  uint uVar1;
  ulonglong uStackX_8;
  uint uStackX_10;
  undefined4 uStackX_14;
  ulonglong auStack_18 [2];
  
  if (_DAT_1820d01c0 == 0x2b992ddfa232) {
    uStackX_8 = 0;
    (*_DAT_1820a0520)(&uStackX_8);
    auStack_18[0] = uStackX_8;
    uVar1 = (*_DAT_1820a0418)();
    auStack_18[0] = auStack_18[0] ^ uVar1;
    uVar1 = (*_DAT_1820a0408)();
    auStack_18[0] = auStack_18[0] ^ uVar1;
    (*_DAT_1820a0698)(&uStackX_10);
    _DAT_1820d01c0 =
         ((ulonglong)uStackX_10 << 0x20 ^ CONCAT44(uStackX_14,uStackX_10) ^ auStack_18[0] ^
         (ulonglong)auStack_18) & 0xffffffffffff;
    if (_DAT_1820d01c0 == 0x2b992ddfa232) {
      _DAT_1820d01c0 = 0x2b992ddfa233;
    }
  }
  _DAT_1820d0200 = ~_DAT_1820d01c0;
  return;
}


