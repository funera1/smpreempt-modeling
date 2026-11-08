# ディレクトリ案内

現在はKeystone ELFのRISC-V命令境界を中心に、PMP状態とHostへの切替を解析しています。LLVM IRや従来の抽象モデルは、それぞれ補助解析と比較用の実装として利用できます。

| 場所 | 責務 | 主なファイル |
| --- | --- | --- |
| `smpreempt/frontend/` | ELF・LLVM IRの読込み、LLVM MCへの接続 | `elf.py`, `llvm.py`, `llvm_mc.py` |
| `smpreempt/extraction/` | 命令一覧、IRのCFG・呼出し展開、区間・ループ要約 | `elf_pmp_inventory.py`, `llvm_transforms.py` |
| `smpreempt/model/` | RISC-V・PMPとLLVM値の部分意味論 | `symbolic_pmp.py`, `riscv_model.py`, `llvm_scalars.py` |
| `smpreempt/analysis/` | 状態の有界実行、切替・Hostアクセス検査、従来BMC | `elf_pmp_steps.py`, `elf_preemption.py`, `symbolic_system.py` |
| `smpreempt/keystone/` | Keystoneのビルド情報取得と固有のIR解析 | `keystone_ir.py`, `ipi_connections.py` |
| `smpreempt/exploration/` | `python -m`で実行するCLIと共通入力処理 | `inspect_elf_pmp.py`, `step_elf_pmp.py`, `check_elf_preemption.py`, `elf_inputs.py` |
| `examples/` | 小さなELF・LLVM IR・PMP初期状態 | `elf/`, `llvm/`, `riscv-memory-ops/` |
| `tests/` | 各抽出器・モデル・CLIの検査 | `test_elf_preemption.py`, `test_elf_pmp_steps.py` |
| `experiments/` | 独立した研究実験 | `semantic_requirements.py` |
| `docs/` | 設計、使い方、過去のモデルと実行記録 | [資料の索引](README.md) |
| `results/` | 生成したELF・IR・JSON・ビルド記録 | [生成物の説明](../results/README.md) |
| `todo.md` | 研究と実装の残作業 | [残作業](../todo.md) |

`analysis/elf_preemption.py`の判定は現在、明示した領域とPMP維持方式に対する有界なHost直接アクセス検査です。`analysis/host_attacks.py`や`analysis/symbolic_system.py`は別の抽象モデルであり、同じ名前の状態や結果を自動的に共有しません。

`docs/current/`に現在の計画・実行結果、`docs/llvm/`にLLVM補助解析、`docs/models/`にモデルの仕様、`docs/history/`に過去の検討を置いています。読む順番は[資料の入口](README.md)を参照してください。

`results/`の研究用ELF・IR・JSONは生成物としてGitの追跡対象から除外しています。ビルド条件とハッシュは各実行記録に残します。CLIの `python -m` 名は維持しています。
