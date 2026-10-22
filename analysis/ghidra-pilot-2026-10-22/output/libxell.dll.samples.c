/* 180009db0 */

undefined8 * FUN_180009db0(undefined8 *param_1,undefined8 *param_2,void *param_3)

{
  undefined8 uVar1;
  undefined8 *puVar2;
  size_t sVar3;
  
  sVar3 = 0xffffffffffffffff;
  do {
    sVar3 = sVar3 + 1;
  } while (*(char *)((longlong)param_3 + sVar3) != '\0');
  puVar2 = thunk_FUN_18000b180(param_2,param_3,sVar3);
  param_1[2] = 0;
  param_1[3] = 0;
  uVar1 = puVar2[1];
  *param_1 = *puVar2;
  param_1[1] = uVar1;
  uVar1 = puVar2[3];
  param_1[2] = puVar2[2];
  param_1[3] = uVar1;
  puVar2[2] = 0;
  puVar2[3] = 0xf;
  *(undefined1 *)puVar2 = 0;
  return param_1;
}


/* 180009e20 */

void * FUN_180009e20(void *param_1,undefined8 *param_2,void *param_3)

{
  undefined8 *puVar1;
  ulonglong uVar2;
  byte local_res10;
  
  uVar2 = 0xffffffffffffffff;
  do {
    uVar2 = uVar2 + 1;
  } while (*(char *)((longlong)param_3 + uVar2) != '\0');
  if (0x7fffffffffffffffU - (longlong)param_2[2] < uVar2) {
                    /* WARNING: Subroutine does not return */
    thunk_FUN_18000b160();
  }
  puVar1 = param_2;
  if (0xf < (ulonglong)param_2[3]) {
    puVar1 = (undefined8 *)*param_2;
  }
  thunk_FUN_18000a3d0(param_1,(ulonglong)local_res10,param_2,puVar1,(void *)param_2[2],param_3,uVar2
                     );
  return param_1;
}


/* 180009ed0 */

void FUN_180009ed0(ulonglong param_1)

{
  longlong lVar1;
  
  if (param_1 + 0x27 <= param_1) {
                    /* WARNING: Subroutine does not return */
    thunk_FUN_18000b130();
  }
  lVar1 = thunk_FUN_180030a80(param_1 + 0x27);
  if (lVar1 == 0) {
                    /* WARNING: Subroutine does not return */
    _invalid_parameter_noinfo_noreturn();
  }
  *(longlong *)((lVar1 + 0x27U & 0xffffffffffffffe0) - 8) = lVar1;
  return;
}


/* 180009f40 */

/* Library Function - Single Match
    void __cdecl std::_Deallocate<16,0>(void * __ptr64,unsigned __int64)
   
   Library: Visual Studio 2019 Release */

void __cdecl std::_Deallocate<16,0>(void *param_1,__uint64 param_2)

{
  void *pvVar1;
  
  pvVar1 = param_1;
  if ((0xfff < param_2) &&
     (pvVar1 = *(void **)((longlong)param_1 + -8),
     0x1f < (ulonglong)((longlong)param_1 + (-8 - (longlong)pvVar1)))) {
                    /* WARNING: Subroutine does not return */
    _invalid_parameter_noinfo_noreturn();
  }
  FUN_180003410(pvVar1);
  return;
}


/* 180009fa0 */

char * FUN_180009fa0(char *param_1,uint param_2)

{
  do {
    param_1 = param_1 + -1;
    *param_1 = (char)param_2 + (char)((ulonglong)param_2 / 10) * -10 + '0';
    param_2 = (uint)((ulonglong)param_2 / 10);
  } while (param_2 != 0);
  return param_1;
}


/* 180009ff0 */

void FUN_180009ff0(undefined8 *param_1,uint param_2)

{
  char *pcVar1;
  undefined1 auStack_58 [32];
  undefined8 *local_38;
  char local_1b [3];
  ulonglong local_18;
  
  local_18 = DAT_18004d028 ^ (ulonglong)auStack_58;
  local_38 = param_1;
  pcVar1 = thunk_FUN_180009fa0(local_1b,param_2);
  param_1[2] = 0;
  param_1[3] = 0xf;
  *(undefined1 *)param_1 = 0;
  if (pcVar1 != local_1b) {
    thunk_FUN_18000b320(param_1,pcVar1,(size_t)(local_1b + -(longlong)pcVar1));
  }
  thunk_FUN_180030c50(local_18 ^ (ulonglong)auStack_58);
  return;
}


/* 18000a090 */

undefined8 * FUN_18000a090(undefined8 *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)thunk_FUN_180030a80(0x10);
  if (puVar1 == (undefined8 *)0x0) {
    *param_1 = 0;
    return param_1;
  }
  *puVar1 = 0x47466558;
  puVar1[1] = 0;
  *param_1 = puVar1;
  return param_1;
}


/* 18000a0e0 */

undefined8 * FUN_18000a0e0(undefined8 *param_1,undefined8 *param_2)

{
  ulonglong uVar1;
  undefined8 uVar2;
  void *_Dst;
  ulonglong uVar3;
  void *local_res8;
  
  param_1[2] = 0;
  param_1[3] = 0;
  uVar1 = param_2[2];
  if (0xf < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  if (uVar1 < 0x10) {
    uVar2 = param_2[1];
    uVar3 = 0xf;
    *param_1 = *param_2;
    param_1[1] = uVar2;
  }
  else {
    uVar3 = uVar1 | 0xf;
    if (0x7fffffffffffffff < uVar3) {
      uVar3 = 0x7fffffffffffffff;
    }
    _Dst = thunk_FUN_180009eb0(uVar3 + 1);
    local_res8 = _Dst;
    thunk_FUN_180009f20(param_1,&local_res8);
    memcpy(_Dst,param_2,uVar1 + 1);
  }
  param_1[2] = uVar1;
  param_1[3] = uVar3;
  return param_1;
}


/* 18000a1b0 */

undefined8 *
FUN_18000a1b0(undefined8 *param_1,undefined8 param_2,undefined8 *param_3,undefined8 *param_4)

{
  ulonglong uVar1;
  ulonglong _Size;
  ulonglong uVar2;
  undefined8 uVar3;
  undefined8 *puVar4;
  ulonglong uVar5;
  void *pvVar6;
  ulonglong uVar7;
  void *local_res8;
  
  param_1[2] = 0;
  param_1[3] = 0;
  _Size = param_3[2];
  uVar2 = param_4[2];
  uVar1 = uVar2 + _Size;
  if ((param_3[3] - _Size < uVar2) || ((ulonglong)param_3[3] < (ulonglong)param_4[3])) {
    if (param_4[3] - uVar2 < _Size) {
      if (0x7fffffffffffffff - _Size < uVar2) {
                    /* WARNING: Subroutine does not return */
        thunk_FUN_18000b160();
      }
      uVar5 = uVar1 | 0xf;
      uVar7 = 0x7fffffffffffffff;
      if ((uVar5 < 0x8000000000000000) && (uVar7 = uVar5, uVar5 < 0x16)) {
        uVar7 = 0x16;
      }
      pvVar6 = thunk_FUN_180009eb0(uVar7 + 1);
      local_res8 = pvVar6;
      thunk_FUN_180009f20(param_1,&local_res8);
      param_1[2] = uVar1;
      param_1[3] = uVar7;
      if (0xf < (ulonglong)param_3[3]) {
        param_3 = (undefined8 *)*param_3;
      }
      memcpy(pvVar6,param_3,_Size);
      if (0xf < (ulonglong)param_4[3]) {
        param_4 = (undefined8 *)*param_4;
      }
      memcpy((void *)((longlong)pvVar6 + _Size),param_4,uVar2 + 1);
    }
    else {
      uVar3 = param_4[1];
      *param_1 = *param_4;
      param_1[1] = uVar3;
      uVar3 = param_4[3];
      param_1[2] = param_4[2];
      param_1[3] = uVar3;
      param_4[2] = 0;
      *(undefined1 *)param_4 = 0;
      param_4[3] = 0xf;
      pvVar6 = (void *)*param_1;
      memmove((void *)((longlong)pvVar6 + _Size),pvVar6,uVar2 + 1);
      if (0xf < (ulonglong)param_3[3]) {
        param_3 = (undefined8 *)*param_3;
      }
      memcpy(pvVar6,param_3,_Size);
      param_1[2] = uVar1;
    }
  }
  else {
    uVar3 = param_3[1];
    *param_1 = *param_3;
    param_1[1] = uVar3;
    uVar3 = param_3[3];
    param_1[2] = param_3[2];
    param_1[3] = uVar3;
    param_3[2] = 0;
    param_3[3] = 0xf;
    *(undefined1 *)param_3 = 0;
    puVar4 = param_1;
    if (0xf < (ulonglong)param_1[3]) {
      puVar4 = (undefined8 *)*param_1;
    }
    if (0xf < (ulonglong)param_4[3]) {
      param_4 = (undefined8 *)*param_4;
    }
    memcpy((void *)((longlong)puVar4 + _Size),param_4,uVar2 + 1);
    param_1[2] = uVar1;
  }
  return param_1;
}


/* 18000a3d0 */

void * FUN_18000a3d0(void *param_1,undefined8 param_2,undefined8 param_3,void *param_4,void *param_5
                    ,void *param_6,size_t param_7)

{
  ulonglong uVar1;
  void *_Size;
  size_t _Size_00;
  ulonglong uVar2;
  void *_Dst;
  ulonglong uVar3;
  
  _Size_00 = param_7;
  _Size = param_5;
  uVar3 = 0xf;
  *(undefined8 *)((longlong)param_1 + 0x10) = 0;
  *(undefined8 *)((longlong)param_1 + 0x18) = 0;
  uVar1 = (longlong)param_5 + param_7;
  _Dst = param_1;
  if (0xf < uVar1) {
    uVar2 = uVar1 | 0xf;
    uVar3 = 0x7fffffffffffffff;
    if ((uVar2 < 0x8000000000000000) && (uVar3 = uVar2, uVar2 < 0x16)) {
      uVar3 = 0x16;
    }
    _Dst = thunk_FUN_180009eb0(uVar3 + 1);
    param_5 = _Dst;
    thunk_FUN_180009f20(param_1,&param_5);
  }
  *(ulonglong *)((longlong)param_1 + 0x10) = uVar1;
  *(ulonglong *)((longlong)param_1 + 0x18) = uVar3;
  memcpy(_Dst,param_4,(size_t)_Size);
  memcpy((void *)((longlong)_Dst + (longlong)_Size),param_6,_Size_00);
  *(undefined1 *)((longlong)_Dst + uVar1) = 0;
  return param_1;
}


/* 18000a4e0 */

longlong * FUN_18000a4e0(longlong *param_1,longlong *param_2,int param_3)

{
  int iVar1;
  
  if (param_3 != 0) {
    *param_1 = (longlong)&DAT_18003cf90;
    iVar1 = *(int *)(*param_2 + 4);
    param_1[7] = (longlong)std::exception::vftable;
    param_1[8] = 0;
    param_1[9] = 0;
    __std_exception_copy((longlong)iVar1 + 8 + (longlong)param_2);
  }
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       XeLL::xellBaseException::vftable;
  *(undefined4 *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) = 0;
  thunk_FUN_18000a0e0(param_1 + 1,param_2 + 1);
  *(int *)(param_1 + 5) = (int)param_2[5];
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       XeLL::ErrorInvalidContext::vftable;
  *(undefined4 *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) = 0;
  return param_1;
}


/* 18000a5c0 */

void FUN_18000a5c0(longlong *param_1,uint param_2,uint param_3,int param_4)

{
  longlong *_Dst;
  longlong lVar1;
  undefined8 *puVar2;
  longlong *plVar3;
  bool bVar4;
  undefined1 auStack_128 [32];
  uint local_108;
  longlong *local_100;
  undefined1 local_f8;
  undefined7 uStack_f7;
  undefined8 local_e8;
  ulonglong local_e0;
  undefined1 local_d8;
  undefined7 uStack_d7;
  undefined8 local_c8;
  ulonglong local_c0;
  undefined1 local_b8;
  undefined7 uStack_b7;
  undefined8 local_a8;
  ulonglong local_a0;
  undefined1 local_98;
  undefined7 uStack_97;
  undefined8 local_88;
  ulonglong local_80;
  undefined1 local_78;
  undefined7 uStack_77;
  undefined8 local_68;
  ulonglong local_60;
  void *local_58 [3];
  ulonglong local_40;
  ulonglong local_38;
  
  local_38 = DAT_18004d028 ^ (ulonglong)auStack_128;
  bVar4 = param_4 != 0;
  if (bVar4) {
    *param_1 = (longlong)&DAT_18003cf90;
    param_1[7] = (longlong)std::exception::vftable;
    param_1[8] = 0;
    param_1[9] = 0;
  }
  local_108 = (uint)bVar4;
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       XeLL::xellBaseException::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x38;
  _Dst = param_1 + 1;
  param_1[4] = 0xf;
  *(undefined1 *)_Dst = 0;
  param_1[3] = 6;
  local_100 = param_1;
  memmove(_Dst,"XeLL: ",6);
  *(undefined1 *)((longlong)param_1 + 0xe) = 0;
  *(undefined4 *)(param_1 + 5) = 0xfffffc18;
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       XeLL::ErrorInvalidContext::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0x38;
  thunk_FUN_180009ff0(local_58,param_3);
  local_108 = bVar4 | 4;
  thunk_FUN_180009ff0((undefined8 *)&local_f8,param_2);
  local_108 = bVar4 | 0xc;
  puVar2 = thunk_FUN_180009e20(&local_78,_Dst,"Invalid Context. Expected ID: ");
  puVar2 = thunk_FUN_180009d80((undefined8 *)&local_98,puVar2,(undefined8 *)&local_f8);
  puVar2 = thunk_FUN_180009db0((undefined8 *)&local_b8,puVar2,". Received: ");
  plVar3 = thunk_FUN_180009d80((undefined8 *)&local_d8,puVar2,local_58);
  if (_Dst != plVar3) {
    if (0xf < (ulonglong)param_1[4]) {
      std::_Deallocate<16,0>((void *)*_Dst,param_1[4] + 1);
    }
    param_1[3] = 0;
    param_1[4] = 0xf;
    *(undefined1 *)_Dst = 0;
    lVar1 = plVar3[1];
    *_Dst = *plVar3;
    param_1[2] = lVar1;
    lVar1 = plVar3[3];
    param_1[3] = plVar3[2];
    param_1[4] = lVar1;
    plVar3[2] = 0;
    plVar3[3] = 0xf;
    *(undefined1 *)plVar3 = 0;
  }
  if (0xf < local_c0) {
    std::_Deallocate<16,0>((void *)CONCAT71(uStack_d7,local_d8),local_c0 + 1);
  }
  local_c8 = 0;
  local_c0 = 0xf;
  local_d8 = 0;
  if (0xf < local_a0) {
    std::_Deallocate<16,0>((void *)CONCAT71(uStack_b7,local_b8),local_a0 + 1);
  }
  local_a8 = 0;
  local_a0 = 0xf;
  local_b8 = 0;
  if (0xf < local_80) {
    std::_Deallocate<16,0>((void *)CONCAT71(uStack_97,local_98),local_80 + 1);
  }
  local_88 = 0;
  local_80 = 0xf;
  local_98 = 0;
  if (0xf < local_60) {
    std::_Deallocate<16,0>((void *)CONCAT71(uStack_77,local_78),local_60 + 1);
  }
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  if (0xf < local_e0) {
    std::_Deallocate<16,0>((void *)CONCAT71(uStack_f7,local_f8),local_e0 + 1);
  }
  local_e8 = 0;
  local_e0 = 0xf;
  local_f8 = 0;
  if (0xf < local_40) {
    std::_Deallocate<16,0>(local_58[0],local_40 + 1);
  }
  *(undefined4 *)(param_1 + 5) = 0xfffffff8;
  thunk_FUN_180030c50(local_38 ^ (ulonglong)auStack_128);
  return;
}


