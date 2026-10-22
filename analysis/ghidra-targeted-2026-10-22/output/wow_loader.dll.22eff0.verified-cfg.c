/* Ghidra output with analyst-supplied CFG and two proved fallthrough annotations.
   Not raw decompilation, not independent verification of the supplied CFG, not original source. */

/* WARNING: Removing unreachable block (ram,0x00018022f125) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int review_export_with_proven_cfg(void)

{
  uint uVar1;
  uint uVar2;
  uint uStack_6c;
  uint uStack_68;
  uint uStack_64;
  uint uStack_60;
  int iStack_5c;
  uint uStack_58;
  int iStack_54;
  int iStack_50;
  uint uStack_4c;
  uint uStack_48;
  uint uStack_44;
  int iStack_40;
  int iStack_3c;
  int iStack_38;
  int iStack_34;
  uint uStack_30;
  int iStack_2c;
  int iStack_28;
  uint uStack_24;
  int iStack_20;
  int iStack_1c;
  int iStack_18;
  int iStack_14;
  
                    /* 0x22eff0  1   */
  uVar1 = _DAT_1821163a4 + 0x624149a5 ^ 0x961d302b;
  uStack_6c = (_DAT_1821163a4 + 0x624149a5 ^ 0xa135c2cd) + (uVar1 + 0x6def6a44 ^ 0xc2d359a2) * -2 +
              _DAT_1821163a4 + uVar1 + 0x6f30bf21 ^ _DAT_1821163a4;
  while( true ) {
    while( true ) {
      while( true ) {
        while (0x57c4e4f3 < (int)uStack_6c) {
          if ((int)uStack_6c < 0x61c43087) {
            if (uStack_6c == 0x57c4e4f4) {
              iStack_2c = uStack_30 * 0x15;
              iStack_28 = ~(uStack_64 | uStack_68) * 0xb;
              uStack_24 = uStack_64 & uStack_68;
              uVar1 = _DAT_1821163cc + 0x13231a81U ^ 0x64d0a0ed;
              uStack_6c = _DAT_1821163cc +
                          ((_DAT_1821163cc + 0x13231a81U ^ 0x46f13afc) + 0xc9ac8a3c ^
                           uVar1 + 0x19f414d9 ^ uVar1) + 0x94752ae4;
            }
            else if (uStack_6c == 0x5afdcfa9) {
              iStack_14 = (uStack_64 & uStack_68) * -9;
              uStack_6c = (_DAT_1821163d8 * 2 - (_DAT_1821163d8 + 0x54159e90U ^ 0x3ceafe76)) +
                          0x502c17dd;
            }
            else {
              iStack_38 = ((iStack_3c - iStack_40) - uStack_4c) + iStack_50;
              uStack_6c = (_DAT_1821163b8 + 0xee4e5657U ^ 0x2f7d50bf) + 0xc63ebe0a;
            }
          }
          else if ((int)uStack_6c < 0x773c6983) {
            if (uStack_6c == 0x61c43087) {
              uStack_68 = _DAT_1820db19c;
              iStack_5c = _DAT_1820db19c + 0xcbd930da;
              uStack_6c = ((_DAT_1821163a8 ^ 0x937c9840) + 0xe99899df ^
                          0x5c24fa9c - (_DAT_1821163a8 + (_DAT_1821163a8 ^ 0x937c9840))) -
                          (_DAT_1821163a8 ^ 0xadccec7c);
            }
            else {
              iStack_20 = ~uStack_24 * 0xb;
              iStack_1c = (uStack_64 | uStack_68) * 0xb;
              uVar1 = _DAT_1821163d0 + 0xb57def5 ^ 0x78b837f3;
              uStack_6c = ((_DAT_1821163d0 + 0xb57def5 ^ _DAT_1821163d0 ^ uVar1 + 0x3a4f0a7a) -
                          _DAT_1821163d0) + uVar1 + 0x88dc6b72;
            }
          }
          else if (uStack_6c == 0x773c6983) {
            uStack_44 = uStack_48 & 0x788d1d6a;
            uStack_6c = 0x91ba3c13 - _DAT_1821163b0;
          }
          else {
            iStack_54 = (uStack_60 & 0x8772e295) * 0xb;
            iStack_50 = (uStack_60 | 0x788d1d6a) * 0xb;
            uStack_6c = 0x86e15219 - _DAT_1821163b4;
          }
        }
        if (0x125d2691 < (int)uStack_6c) break;
        if (uStack_6c == 0x194a331) {
          iStack_18 = (~uStack_68 & uStack_64) * 0x15;
          uStack_6c = 0xb96611a - (_DAT_1821163d4 ^ 0x518ab9b0) ^ _DAT_1821163d4 ^ 0x518ab9b0 ^
                      0xb99dd149;
        }
        else if (uStack_6c == 0xda873db) {
          uStack_64 = iStack_34 + uStack_58;
          uStack_30 = ~(~uStack_68 | uStack_64);
          uStack_6c = _DAT_1821163c8 + (_DAT_1821163c8 ^ 0x7154159c) + 0xbc3186f9 ^
                      _DAT_1821163c8 + 0x297dc64 ^ _DAT_1821163c8 + 0xf0b9d553 ^ 0x783fc372;
        }
        else {
          iStack_40 = uStack_44 * 9;
          iStack_3c = (uStack_60 & 0x788d1d6a) * -0xb;
          uVar1 = _DAT_1821163c0 + 0xf41b1e74U ^ 0xa221fbfa;
          uStack_6c = ((uVar1 + 0x86921423 ^ uVar1 + 0x3a0887b7) + _DAT_1821163c0) -
                      (_DAT_1821163c0 + 0xf41b1e74U);
        }
      }
      if (0x1d7603db < (int)uStack_6c) break;
      if (uStack_6c == 0x125d2692) {
        iStack_34 = iStack_38 - iStack_54;
        uVar1 = (_DAT_1821163c4 ^ 0xea411941) + 0xc0275f89;
        uVar2 = uVar1 ^ 0xf1e6b0ce;
        uStack_6c = ((uVar2 - uVar1) + 0x5cf41101 ^ _DAT_1821163c4 ^ 0xea411941 ^ uVar2) +
                    _DAT_1821163c4;
      }
      else {
        uStack_60 = iStack_5c + 0x79a5e4;
        uStack_58 = uStack_60 ^ 0x9ea46c82;
        uVar1 = _DAT_1821163ac + 0xd8a2d417 ^ 0x765d7492;
        uStack_6c = (0x17b66935 - _DAT_1821163ac ^ _DAT_1821163ac ^ uVar1) + uVar1 * 3 + 0x56171210;
      }
    }
    if (uStack_6c != 0x47555d1f) break;
    uStack_4c = uStack_60 ^ 0x788d1d6a;
    uStack_48 = ~uStack_60;
    uStack_6c = _DAT_1821163bc + (_DAT_1821163bc ^ 0x8d9744b6) + 0xe594d2cd;
  }
  return (((iStack_14 - iStack_18) + iStack_1c + iStack_20) - iStack_28) - iStack_2c;
}


