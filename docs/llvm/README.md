# LLVM IRによる補助解析

LLVM IRは、ELF上の命令だけでは分かりにくい管理構造、データフロー、呼出し関係を調べるための補助入力です。IRの命令境界と最終ELFの機械命令境界は区別します。

- [LLVM命令とCFGの抽出](LLVM_TRANSITIONS.md)
- [呼出し展開とループ要約](LLVM_ANALYSIS.md)
- [LLVM状態遷移の有界実行](LLVM_BOUNDED_EXECUTION.md)
- [抽象状態モデルへの対応付け](ABSTRACT_TRANSITIONS.md)
- [PMP操作とLLVM IRの対応](RISCV_PMP_LLVM_IR.md)
- [Keystone/OpenSBIのIR取得](KEYSTONE_BATCH_CAPTURE.md)
- [KeystoneのIR抽出結果](KEYSTONE_EXTRACTION_RESULTS.md)
- [共有CFGとIPI callback](SHARED_CFG_IPI.md)

[資料の入口に戻る](../README.md)
