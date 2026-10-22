/* Ghidra output with analyst-supplied CFG and one proved fallthrough annotations.
   Not raw decompilation, not independent verification of the supplied CFG, not original source. */

/* WARNING: Removing unreachable block (ram,0x000181beb9a3) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 review_application_with_proven_cfg(undefined8 param_1,int param_2,longlong param_3)

{
  char cVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  uint uVar4;
  ulonglong uVar5;
  uint uStack_14;
  
  uVar4 = (_DAT_182183c04 ^ 0xcb5f91d6) + 0x7f558308;
  uVar5 = (ulonglong)uVar4;
  uStack_14 = (((uVar4 ^ 0x9e5388dd) + 0xe6dabf2f ^ uVar4) - (_DAT_182183c04 ^ 0xcb5f91d6)) +
              _DAT_182183c04;
  while( true ) {
    if (uStack_14 != 0x2e54bb30) {
      if (uStack_14 == 0x4d94533b) {
        FUN_180ecad40(0x3a,CONCAT71((int7)(uVar5 >> 8),param_3 != 0),0x30,0x14);
      }
      else {
        uVar2 = FUN_1817df7f0(0x10,0x1e,0x42);
        uVar3 = (*_DAT_1820a0400)();
        (*_DAT_1820a0798)(uVar3,uVar2);
      }
      return 1;
    }
    if (param_2 != 0) break;
    cVar1 = FUN_181a70790(0x20,0x20,0x5a);
    if (cVar1 == '\0') {
      uVar4 = _DAT_182183c08 + 0xe914315d ^ 0xc9211704;
      uVar5 = (ulonglong)(uVar4 + 0xcd4a637e);
      uStack_14 = (uVar4 + 0x900cb923 ^ 0xa3c5cd21 - uVar4 ^ uVar4 + 0xcd4a637e) + _DAT_182183c08 +
                  0xe914315d ^ _DAT_182183c08;
    }
    else {
      uVar4 = _DAT_182183c0c + 0x672fea88;
      uVar5 = (ulonglong)uVar4;
      uStack_14 = ((uVar4 ^ 0x60dc3c60) + 0x5b4586dc ^ uVar4 ^
                   0xdedd418 - (uVar4 ^ 0x60dc3c60) ^ _DAT_182183c0c + 0x51967e92U ^ 0x434438b3) +
                  _DAT_182183c0c;
    }
  }
  if (param_2 == 1) {
    FUN_180e79a80(0x45,0x2c,0x2b);
    return 1;
  }
  if (param_2 == 2) {
    FUN_180937970(6,0x32,0x16);
    return 1;
  }
  if (param_2 == 3) {
    FUN_18116f060(0x60,0x3e,0x36);
    return 1;
  }
  return 1;
}


