/* Raw Ghidra output, analyst-supplied extent; no semantic recovery claim. */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void review_parse_fallback_candidate(undefined8 param_1,undefined2 param_2)

{
  undefined4 uVar1;
  code *pcVar2;
  ushort uVar3;
  longlong unaff_RSI;
  undefined4 *unaff_RDI;
  
  pcVar2 = (code *)swi(0xf5);
  uVar3 = (*pcVar2)();
  uVar1 = in(param_2);
  *unaff_RDI = uVar1;
  _DAT_9551a349871839dc = uVar3 | 0x69;
  *(char *)(unaff_RSI + 0x31ce0347) = *(char *)(unaff_RSI + 0x31ce0347) - (char)(uVar3 >> 8);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


