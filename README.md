# RISC-Vセキュアモニタのプリエンプション解析

KeystoneのELFからRISC-V命令と状態遷移を取り出し、各命令境界でHostに切り替えた場合の安全性と、プリエンプションを禁止すべき地点を調べる研究用コードです。

現在は、**PMPを維持して切り替える方式**について、指定したメモリ領域へのHostの直接R/Wを有界に検査できます。実際のPM、同期キャッシュ、再開後の実行、保護領域の自動導出は未接続です。

## まず見る資料

| 知りたいこと | 資料 |
| --- | --- |
| 研究の目標と残っていること | [全体計画](docs/current/PREEMPTION_REGION_PLAN.md) ・ [TODO](todo.md) |
| 現在の安全性検査の使い方と結果の読み方 | [命令境界の検査](docs/current/ELF_PREEMPTION_BOUNDARIES.md) |
| Keystoneの実ELFで何を確認したか | [実行結果](docs/current/KEYSTONE_ELF_REAL_RUN.md) |
| コードの配置やその他の資料 | [ディレクトリ案内](docs/DIRECTORY_LAYOUT.md) ・ [資料一覧](docs/README.md) |

## 小さな例を実行する

Python、Z3、LLVM 18または20の共有ライブラリを使います。リポジトリのルートで実行してください。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-smt.txt
python3 -m examples.elf.build_pmp_fixture /tmp/smpreempt-pmp-demo.elf
.venv/bin/python -m smpreempt.exploration.check_elf_preemption \
  /tmp/smpreempt-pmp-demo.elf --function pmp_demo \
  --pmp-json examples/elf/pmp_entry0_napot_16.json --reg x11=0 \
  --region-base 0x8000 --region-size 8 --assume-fresh-pmp
```

`abstract_counterexample`はモデル上でHostがアクセス可能な状態の候補、`no_counterexample_within_bound`は指定範囲で反例が見つからなかった結果です。未対応の処理や探索の打切りは`unknown`として残します。詳しい前提は[命令境界の検査](docs/current/ELF_PREEMPTION_BOUNDARIES.md)を参照してください。

## 実装の入口

- `smpreempt/frontend/`：ELF・LLVM IRの読込みと命令デコード
- `smpreempt/analysis/`：ELFの記号実行と命令境界の検査
- `smpreempt/model/`：PMPや命令の部分意味論
- `smpreempt/exploration/`：`python -m`で実行するコマンド
- `examples/`・`tests/`：再現用の入力とテスト
- `results/`：研究用ELFや解析結果の生成物

テストは `.venv/bin/python -m unittest discover -q` で実行できます。
