/* 14013e800 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00014013e77e) */

void FUN_14013e800(undefined8 param_1,longlong param_2)

{
  undefined8 *puVar1;
  longlong lVar2;
  char cVar3;
  uint uVar4;
  ulonglong uVar5;
  ulonglong in_RAX;
  uint *puVar6;
  longlong unaff_RBX;
  longlong *plVar7;
  undefined8 *puVar8;
  uint uVar9;
  undefined8 *unaff_RBP;
  undefined8 uVar10;
  uint unaff_ESI;
  undefined4 unaff_00000034;
  char *unaff_RDI;
  char in_CF;
  bool bVar11;
  bool bVar12;
  float10 in_ST1;
  float10 in_ST3;
  float10 in_ST5;
  float10 fVar13;
  float10 in_ST7;
  
  *unaff_RDI = *unaff_RDI + (char)param_2 + in_CF;
  bVar11 = (char)param_2 == '\0';
  puVar6 = (uint *)CONCAT71((int7)(in_RAX >> 8),*(undefined1 *)(unaff_RBX + (in_RAX & 0xff)));
  do {
    ffree(in_ST7);
    uVar10 = *unaff_RBP;
    plVar7 = unaff_RBP + 1;
    if (bVar11) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    out(0xad,(char)puVar6);
    bVar12 = false;
    *puVar6 = *puVar6 & (uint)puVar6;
    uVar9 = *puVar6;
    bVar11 = *puVar6 == 0;
    uVar5 = (ulonglong)unaff_RDI & 0xffffffff;
    unaff_RDI = (char *)((ulonglong)puVar6 & 0xffffffff);
    if (0 < (int)*puVar6) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    do {
      lVar2 = *plVar7;
      if (!bVar11 && bVar12 == (int)uVar9 < 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      cVar3 = in((short)param_2);
      *unaff_RDI = cVar3;
      cVar3 = in((short)param_2);
      uVar5 = CONCAT71((int7)(uVar5 >> 8),cVar3);
      puVar6 = (uint *)(unaff_RDI + 2);
      unaff_RDI[1] = cVar3;
      plVar7 = (longlong *)(lVar2 + -8);
      *(longlong *)(lVar2 + -8) = param_2;
      unaff_RDI = unaff_RDI + 6;
      uVar4 = (uint)uVar5;
      bVar12 = SBORROW4(uVar4,*puVar6);
      uVar9 = uVar4 - *puVar6;
      bVar11 = uVar4 == *puVar6;
    } while (bVar11 || (int)uVar4 < (int)*puVar6);
    puVar8 = (undefined8 *)
             (ulonglong)
             ((((int)lVar2 + -8) - *(int *)(CONCAT44(unaff_00000034,unaff_ESI) + 0x2a8bcd8a)) -
             (uint)(uVar4 < 0x1757fc03 || uVar4 + 0xe8a803fd < (uint)(uVar4 < *puVar6)));
    uVar9 = (uint)uVar10 & *(uint *)(param_2 + 0x3864b7fc);
    bVar11 = uVar9 == 0;
    fVar13 = in_ST1 + in_ST7;
    puVar6 = (uint *)*puVar8;
    unaff_RBP = (undefined8 *)(ulonglong)unaff_ESI;
    in_ST1 = in_ST3;
    in_ST3 = in_ST5;
    in_ST5 = in_ST7;
    in_ST7 = fVar13;
  } while ((int)uVar9 < 1);
  *puVar8 = unaff_RBP;
  cVar3 = '\r';
  puVar1 = puVar8;
  do {
    unaff_RBP = unaff_RBP + -1;
    puVar1 = puVar1 + -1;
    *puVar1 = *unaff_RBP;
    cVar3 = cVar3 + -1;
  } while ('\0' < cVar3);
  puVar8[-0xe] = puVar8;
  *(ulonglong *)((longlong)puVar8 + -0x5dd2) = CONCAT44(unaff_00000034,unaff_ESI);
  return;
}


/* 14013eaa0 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00014013ea3d) */
/* WARNING: Removing unreachable block (ram,0x00014013ea42) */
/* WARNING: Removing unreachable block (ram,0x00014013ea4a) */

void FUN_14013eaa0(undefined8 param_1,longlong param_2)

{
  char *pcVar1;
  ulonglong in_RAX;
  ulonglong uVar2;
  undefined8 unaff_RBX;
  undefined4 *unaff_RSI;
  undefined4 *unaff_RDI;
  int unaff_R14D;
  
  *unaff_RDI = *unaff_RSI;
  pcVar1 = (char *)(param_2 + (longlong)(unaff_RSI + 1) * 4);
  *pcVar1 = *pcVar1 + (char)(in_RAX >> 8);
  uVar2 = (longlong)(param_2 << 0x20 | in_RAX & 0xffffffff) / (longlong)unaff_R14D & 0xffffffff;
  LOCK();
  *(char *)(uVar2 - 0x6c) = (char)((ulonglong)unaff_RBX >> 8);
  UNLOCK();
  *(char *)(unaff_RDI + 1) = (char)uVar2 + '\\';
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


/* 14013f330 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x00014013f33f) overlaps instruction at (ram,0x00014013f33e)
    */
/* WARNING: Removing unreachable block (ram,0x00014013f2a5) */

int FUN_14013f330(undefined8 param_1,undefined2 param_2)

{
  int iVar1;
  int in_EAX;
  undefined1 unaff_BL;
  undefined1 unaff_BH;
  undefined6 unaff_0000001a;
  ulonglong unaff_RBP;
  longlong unaff_RDI;
  
  if ((POPCOUNT(in_EAX + 0x5a6c3208U & 0xff) & 1U) == 0) {
    do {
                    /* WARNING: Do nothing block with infinite loop */
    } while( true );
  }
  if (in_EAX + 0x5a6c3208U != 0 && -0x5a6c3209 < in_EAX) {
    out(param_2,0xadebf533);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  *(char *)(CONCAT62(unaff_0000001a,CONCAT11(unaff_BH,unaff_BL)) + unaff_RDI) =
       (char)((unaff_RBP & 0xffffffff) >> 8);
  *(int *)CONCAT62(unaff_0000001a,CONCAT11(unaff_BH,unaff_BL)) =
       *(int *)CONCAT62(unaff_0000001a,CONCAT11(unaff_BH,unaff_BL)) + 0x6a;
  iVar1 = (int)CONCAT71((int7)((unaff_RBP & 0xffffffff) >> 8),0xe0) + 0x764e025a;
  out(param_2,iVar1);
  return iVar1;
}


/* 14013f6a0 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_14013f6a0(longlong param_1,ulonglong param_2)

{
  undefined1 uVar1;
  char cVar2;
  ulonglong in_RAX;
  uint uVar3;
  longlong unaff_RSI;
  undefined8 unaff_R14;
  undefined1 *unaff_retaddr;
  undefined1 auStackX_8 [32];
  
  cVar2 = *(char *)(in_RAX - 4);
  LOCK();
  uVar1 = *unaff_retaddr;
  *unaff_retaddr = (char)(param_2 & 0xffffffff);
  UNLOCK();
  if ((POPCOUNT((char)(param_2 >> 8) - cVar2) & 1U) == 0) {
    *(uint *)(unaff_RSI + 4) = *(uint *)(unaff_RSI + 4) >> 1;
    *(char *)(ulonglong)
             (((int)CONCAT71((int7)((param_2 & 0xffffffff) >> 8),uVar1) + 0x2f734335U ^ 0x6e606163)
             & 0xabf75bdd) = (char)((ulonglong)param_1 >> 8);
    uVar3 = (uint)auStackX_8 ^ _DAT_19b242066;
    *(byte *)(param_1 + 0x5b6aff08) =
         *(byte *)(param_1 + 0x5b6aff08) | (byte)((in_RAX & 0xffffffff) >> 8);
    DAT_107fe4424 = DAT_107fe4424 - (char)(in_RAX & 0xffffffff);
    *(undefined8 *)((ulonglong)uVar3 - 8) = unaff_R14;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


/* 14013f790 */

/* WARNING: Control flow encountered bad instruction data */

void FUN_14013f790(longlong param_1,undefined8 param_2)

{
  char *pcVar1;
  uint *puVar2;
  uint uVar4;
  uint uVar3;
  undefined1 uVar5;
  code *pcVar6;
  int in_EAX;
  undefined1 uVar7;
  undefined1 uVar8;
  undefined2 uVar9;
  undefined4 uVar10;
  longlong lVar11;
  char unaff_BL;
  ulonglong uVar12;
  longlong unaff_RBP;
  longlong unaff_RSI;
  longlong unaff_RDI;
  byte in_CF;
  char cVar13;
  
  uVar10 = (undefined4)((ulonglong)param_1 >> 0x20);
  uVar9 = (undefined2)((ulonglong)param_1 >> 0x10);
  uVar8 = (undefined1)((ulonglong)param_1 >> 8);
  uVar7 = (undefined1)param_1;
  uVar12 = (ulonglong)(in_EAX + (int)param_2 + (uint)in_CF);
  uVar5 = *(undefined1 *)(unaff_RDI + unaff_RBP * 8);
  out(*(undefined4 *)(unaff_RSI + 1),(short)CONCAT71((int7)((ulonglong)param_2 >> 8),uVar5));
  *(undefined8 *)(uVar12 - 8) = 0x7f0ba1e;
  lVar11 = CONCAT62((int6)((ulonglong)param_2 >> 0x10),
                    CONCAT11((byte)((ulonglong)param_2 >> 8) | *(byte *)(unaff_RDI + -0x44),uVar5));
  *(undefined8 *)(uVar12 - 0x10) = 0xffffffffffffffa8;
  pcVar1 = (char *)(lVar11 + 0x20);
  cVar13 = *pcVar1;
  *pcVar1 = *pcVar1 << 1;
  puVar2 = (uint *)(unaff_RSI + 0x45);
  uVar3 = *puVar2;
  uVar4 = *puVar2;
  *puVar2 = uVar4 + 0x47feb949 + (uint)(cVar13 < '\0');
  if ((uVar3 < 0xb80146b7 && !CARRY4(uVar4 + 0x47feb949,(uint)(cVar13 < '\0'))) && *puVar2 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  *(longlong *)(uVar12 - 0x18) = unaff_RSI + 5;
  uVar4 = (uint)param_1;
  puVar2 = (uint *)(param_1 + 0x48);
  cVar13 = CARRY4(*puVar2,uVar4);
  uVar3 = *puVar2;
  *puVar2 = *puVar2 + uVar4;
  if (*puVar2 == 0 || SCARRY4(uVar3,uVar4) != (int)*puVar2 < 0) {
    pcVar6 = (code *)swi(200);
    (*pcVar6)(uVar7,(uint)lVar11 | uRam00000000127df542);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  *(undefined8 *)(uVar12 - 0x18) = 0x14013f87d;
  func_0x0001257f0e9f();
  DAT_1905ac4ef = (DAT_1905ac4ef - unaff_BL) - cVar13;
  *(ulonglong *)(uVar12 - 0x18) = CONCAT44(uVar10,CONCAT22(uVar9,CONCAT11(uVar8,uVar7)));
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


/* 14013fb90 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00014013fc96) */
/* WARNING: Removing unreachable block (ram,0x31eab013) */
/* WARNING: Removing unreachable block (ram,0x00014013fc8a) */

void FUN_14013fb90(longlong param_1,char *param_2)

{
  byte *pbVar1;
  int *piVar2;
  undefined1 uVar3;
  char cVar4;
  byte bVar5;
  uint uVar6;
  undefined4 *unaff_RSI;
  uint unaff_EDI;
  int in_R10D;
  longlong unaff_R13;
  char unaff_R14B;
  undefined7 unaff_000000b1;
  
  uVar6 = unaff_EDI ^ 0x43d4a73;
  out(200,uVar6);
  out(*unaff_RSI,(short)param_2);
  LOCK();
  uVar3 = *(undefined1 *)(param_1 + -0x43);
  *(undefined1 *)(param_1 + -0x43) = (char)uVar6;
  UNLOCK();
  cVar4 = *param_2;
  pbVar1 = (byte *)(unaff_R13 + 0x20d15474);
  bVar5 = *pbVar1;
  *pbVar1 = (char)*pbVar1 >> 1;
  param_2[-0x988f441] = -0x59;
  param_2[-0x988f440] = -0x61;
  param_2[-0x988f43f] = -0x58;
  param_2[-0x988f43e] = -0x52;
  if ((bool)(bVar5 & 1)) {
    uRam000000003024b2bf = CONCAT31((int3)(uVar6 >> 8),uVar3) ^ 0xb5;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  piVar2 = (int *)(CONCAT71(unaff_000000b1,unaff_R14B + cVar4) + 0x72b7b3);
  *piVar2 = *piVar2 + in_R10D;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


/* 14013fe10 */

/* WARNING: Control flow encountered bad instruction data */

void FUN_14013fe10(undefined8 param_1,undefined1 param_2)

{
  char *pcVar1;
  char cVar2;
  undefined1 in_AL;
  undefined4 *unaff_RSI;
  undefined4 *unaff_RDI;
  longlong in_R10;
  
  *unaff_RDI = *unaff_RSI;
  pcVar1 = (char *)(in_R10 + 0xccbfdc2);
  DAT_5d082277650edbbd = in_AL;
  *pcVar1 = *pcVar1 + ';';
  cVar2 = *pcVar1;
  *(undefined1 *)(unaff_RDI + 1) = in_AL;
  if (cVar2 < '\0') {
    out(*(undefined1 *)((longlong)unaff_RSI + 5),CONCAT11(0x38,param_2));
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


/* 14015eb10 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x00014015eb2a) overlaps instruction at (ram,0x00014015eb25)
    */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_14015eb10(byte param_1,longlong param_2)

{
  char *pcVar1;
  char cVar2;
  undefined4 uVar3;
  code *pcVar4;
  longlong in_RAX;
  char unaff_BH;
  undefined8 *puVar5;
  undefined8 *puVar6;
  undefined8 *unaff_RBP;
  undefined8 *puVar7;
  longlong unaff_RSI;
  longlong in_R10;
  bool bVar8;
  
  puVar7 = (undefined8 *)*unaff_RBP;
  puVar5 = unaff_RBP + 1;
  pcVar1 = (char *)((longlong)puVar7 + -0x29);
  *pcVar1 = *pcVar1 - unaff_BH;
  cVar2 = *pcVar1;
  pcVar1 = (char *)(in_RAX + -10 + (longlong)puVar7 * 4);
  param_1 = param_1 & 0x1f;
  *pcVar1 = *pcVar1 >> param_1;
  DAT_1f9f452aa24c8df1 = (undefined1)in_RAX;
  if ((param_1 != 0 || -1 < cVar2) && (param_1 == 0 || -1 < *pcVar1)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  do {
    LOCK();
    uVar3 = *(undefined4 *)(in_R10 + -0x2f4b0b8);
    *(undefined4 *)(in_R10 + -0x2f4b0b8) = (int)puVar5;
    puVar5 = (undefined8 *)CONCAT44((int)((ulonglong)puVar5 >> 0x20),uVar3);
    UNLOCK();
    bVar8 = _DAT_120d70174 < (uint)in_RAX;
    _DAT_120d70174 = _DAT_120d70174 - (uint)in_RAX;
  } while (bVar8 || _DAT_120d70174 == 0);
  *(ulonglong *)(unaff_RSI + -0x3eab327e) = *(ulonglong *)(unaff_RSI + -0x3eab327e) | 0x610749ed;
  pcVar4 = *(code **)(param_2 + -9);
  *(undefined8 *)((longlong)puVar5 + -8) = 0x14015eb43;
  (*pcVar4)();
  puVar6 = (undefined8 *)((longlong)puVar5 + -8);
  *(undefined8 **)((longlong)puVar5 + -8) = puVar7;
  cVar2 = '\x0f';
  do {
    puVar7 = puVar7 + -1;
    puVar6 = puVar6 + -1;
    *puVar6 = *puVar7;
    cVar2 = cVar2 + -1;
  } while ('\0' < cVar2);
  *(undefined1 **)((longlong)puVar5 + -0x88) = (undefined1 *)((longlong)puVar5 + -8);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


