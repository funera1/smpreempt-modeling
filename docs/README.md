# 資料の入口

最初に読む資料は、知りたいことに合わせて選んでください。

| 知りたいこと | 資料 |
| --- | --- |
| 何を目指していて、何が残っているか | [全体計画](current/PREEMPTION_REGION_PLAN.md) ・ [TODO](../todo.md) |
| 今の検査をどう使い、結果をどう読むか | [命令境界の検査](current/ELF_PREEMPTION_BOUNDARIES.md) |
| 実際のKeystone ELFで何が分かったか | [実行結果](current/KEYSTONE_ELF_REAL_RUN.md) |
| ELFから命令を取り出す方法 | [ELFの抽出と実行](current/KEYSTONE_ELF.md) |

その他の資料は目的ごとにまとめています。

- [LLVM IRによる補助解析](llvm/README.md)：CFG、呼出し、管理構造を調べる資料。
- [操作・安全性のモデル](models/README.md)：RISC-V操作、PMP同期、メモリ安全性の仕様。
- [過去の検討と実験](history/README.md)：従来の抽象状態モデルやBMC。
- [ディレクトリ案内](DIRECTORY_LAYOUT.md)：コード・入力・結果の配置。
