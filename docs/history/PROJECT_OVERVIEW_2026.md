> 2026年11月の整理前のREADMEです。現在の入口は[ルートREADME](../../README.md)を参照してください。

# RISC-V SM preemption verification

現在の主な作業は、**KeystoneのELFからRISC-V命令境界を抽出し、プリエンプション後のHostアクセスを検討すること**です。
命令ごとの状態変化と、入力・機構・ハードウェアに関する仮定を記録します。
現在の境界検査は、PMPを維持する切替方式と明示した領域への直接R/Wに限定した有界解析です。
使い方は[命令境界の検査](../current/ELF_PREEMPTION_BOUNDARIES.md)、資料全体は[資料の索引](../README.md)、コード配置は[ディレクトリ案内](../DIRECTORY_LAYOUT.md)を参照してください。

RISC-Vセキュアモニタの安全なプリエンプションを検討する研究用モデルです。
目標は、共通PMの切替操作と中断可能条件を導き、その制約を減らすSM構造を考えることです。
研究の前提・方針は [RESEARCH_DIRECTION.md](RESEARCH_DIRECTION.md) を参照してください。
現在の再検討は [意味に基づくメモリ安全性](../models/SEMANTIC_MEMORY_MODEL.md) を参照してください。
アクセス履歴による保護判定に代わり、秘密への依存と再開後の信頼された使用から制限を導く方針です。
`python3 -m experiments.semantic_requirements` で最小の記号実験を実行できます。
この実験は統合探索器とは別で、既存の `attacks` / `states` の判定は従来の領域ポリシーのままです。
表現可能な中断状態を対象とした従来モデルと、Hostだけで完結する直接アクセスの解析も残しています。
それぞれの結果は対象・前提が異なるため、実装ELFに対する境界検査と区別して扱います。

## 構成

[深さ制限のない共有CFGとIPI接続](../llvm/SHARED_CFG_IPI.md) は `--abstract-model --shared-calls` で抽出できます。

Keystone/OpenSBIの入力を揃える場合は [全Cファイルの一括IR取得](../llvm/KEYSTONE_BATCH_CAPTURE.md) を使います。

[抽象状態モデルへの対応付け](../llvm/ABSTRACT_TRANSITIONS.md) は
`python3 -m smpreempt.exploration.extract_llvm INPUT.ll --abstract-model --function NAME`
で実行できます。CFG・由来・状態変数への作用・未解決の仮定を出力します。
一関数の命令状態を有界実行する試作は [LLVM状態遷移の実行](../llvm/LLVM_BOUNDED_EXECUTION.md) を参照してください。

実装非依存の出発点として、[RISC-Vメモリ操作の遷移語彙](../models/RISCV_MEMORY_OPERATIONS.md) を追加しています。
`python3 -m smpreempt.exploration.riscv_memory_operations` で22操作群を列挙し、
`--input examples/riscv-memory-ops/pmp-update.json` でCSR・フェンス等を命令境界付きの操作列へ正規化します。
これは宣言的なモデル表現で、一覧全体の実行器や攻撃検査ではありません。
PMPに関係する操作群をLLVM IR命令へ対応付ける粒度と規則は [RISCV_PMP_LLVM_IR.md](../llvm/RISCV_PMP_LLVM_IR.md) を参照してください。

アクセス権を評価せずに実装の演算・メモリ操作・分岐を取り出す入口として、
[LLVM IRの遷移抽出](../llvm/LLVM_TRANSITIONS.md) を追加しました。
`python3 -m smpreempt.exploration.extract_llvm examples/llvm/erase.ll --function erase`
で命令単位の遷移グラフを出力します。ループは展開せず保持し、呼出しやアセンブリは意味の追加が必要な操作として残します。
LLVM 18/20の共有ライブラリを使用し、LLVM実行器・安全性検査とは分けています。
呼出し展開、メモリ区間・ループ要約、限定的な実行意味論と、実際のKeystone generic構成での接続は
[LLVM_ANALYSIS.md](../llvm/LLVM_ANALYSIS.md) にまとめています。

実装バイナリからの入口として、[Keystone/RV64 ELFの抽出と読取検査](../current/KEYSTONE_ELF.md) を追加しています。
`python3 -m smpreempt.exploration.explore_elf SM.elf --entry destroy_enclave`
で命令と後続PC候補をJSONへ抽出できます。未対応命令も残し、解析完了とは扱いません。
`python3 -m smpreempt.exploration.inspect_elf_pmp SM.elf --function pmp_unset` はLLVM MCを使った指定関数の命令表示とPMP関連CSRの分類を出します。
generic研究用Keystone ELFの`pmp_unset`について、命令抽出・限定的な記号実行とSailとの比較例を[記録](../current/KEYSTONE_ELF_REAL_RUN.md)しています。読取検査の実ELF適用は未実施です。
各命令境界でのHost直接アクセスの限定検査は [ELF_PREEMPTION_BOUNDARIES.md](../current/ELF_PREEMPTION_BOUNDARIES.md) を参照してください。

```text
smpreempt/
  frontend/      # LLVM/ELFの読込み、命令とCFGの抽出
  extraction/    # 呼出し展開、区間・ループ要約、inline asmの操作抽出
  model/         # RISC-V操作語彙、具体・記号状態、LLVMの値とメモリ
  keystone/      # KeystoneのIRビルド取得、PMP実装への接続
  analysis/      # ELF状態実行、命令境界検査、従来の探索／検証
  exploration/   # CLI入口とELF実行用の共通入力処理
  scenarios.py   # デモ・テスト用シナリオ
tests/           # 抽出の整合性・意味論・既存解析の回帰テスト
examples/        # 小さなLLVM/ELF/操作列の入力例
experiments/     # 独立した研究実験
docs/            # 定義・抽出手順・過去の検証結果
results/         # 生成結果（コードとは分離）
todo.md          # 残作業
```

## 実行

リポジトリのルートから実行します。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-smt.txt
python3 -m examples.elf.build_pmp_fixture /tmp/smpreempt-pmp-demo.elf
.venv/bin/python -m smpreempt.exploration.check_elf_preemption \
  /tmp/smpreempt-pmp-demo.elf --function pmp_demo \
  --pmp-json examples/elf/pmp_entry0_napot_16.json --reg x11=0 \
  --region-base 0x8000 --region-size 8 --assume-fresh-pmp
```

全テストと、従来のHost直接アクセス解析を実行する場合:

```sh
.venv/bin/python -m unittest -v
.venv/bin/python -m smpreempt.exploration.explore_system --analysis attacks
```

記号解析とそのテストにはZ3が必要です。ELFのLLVM MC利用にはLLVM 18または20の共有ライブラリが必要です。

## 従来モデルの探索

既定の `--analysis attacks` は、任意の中断状態からWoutでHostへ渡し、
Hostの読取・書換えだけで保護対象へのアクセスが成立するかを調べます。
G・再開・新規呼出しを使わず、PMP設置不能やHost入口の権限不足は攻撃と分けて報告します。
反例にはHostのLBU/SBと、読取値または変更前後の値を出し、具体モデルで対象バイトを再実行します。
PMPとRがHost実行中に不変なBare通常データ操作に限定し、命令数の上限は置きません。
定義と結果の読み方は [HOST_ONLY_ATTACKS.md](HOST_ONLY_ATTACKS.md) を参照してください。

PMP同期不足は別モードで比較します。

```sh
.venv/bin/python -m smpreempt.exploration.explore_system --analysis pmp-sync
```

現在のPMPは対象を拒否するが、過去の合法なS-modeアクセスの許可が残った状態を使います。
同期なしでは古い許可による読取・書換えが成立し、全体SFENCE.VMAありでは同じ条件の反例が消えます。
代表エントリ1件の抽象モデルで、Sv39のページウォークや実機TLBの再現ではありません。
`attacks`の既定は従来のキャッシュなし抽象化です。
仕様根拠とキャッシュ来歴は [PMP_SYNCHRONIZATION.md](../models/PMP_SYNCHRONIZATION.md) を参照してください。

`--analysis states` は従来の補助的なW/G検証です。
SM命令列や初期値を固定せず、記号状態K0から切替を検査します。
固定PMPテンプレートという機構Wに対し、無条件のG（always）と、隔離等を確認するG（isolation）を比較します。
設置/復元可能性、Host入口のX権限、直接隔離、保護バイトの完全性、GPR初期化、CPU/PMP復元を個別に検証します。
各checksのsatはその条件の反例、unsatは定義したK0に対するその条件の成立です。
許可状態の存在も調べ、全状態拒否を成功と扱いません。
K0と保証の範囲は [MODEL.md](MODEL.md) を参照してください。

命令BMCを使う場合は明示的に選びます。

```sh
.venv/bin/python -m smpreempt.exploration.explore_system --analysis program --bound 5 --timeout-ms 30000
```

固定した初期状態とPC→命令マップに対して、次を記号的に選びます。

- C/SMの命令実行と中断位置。
- HostのLD/SDのアドレス・書込値と、SMへの再開。
- 繰り返し中断・再開を含む操作列。

検査するのは、Host状態で `R_fixed ∪ A` が直接R/W可能にならないことです。
AはC/SMが成功したLD/SDで触った物理バイトの累積履歴です。
見つかった反例は具体モデルで再実行し、状態の対応を検査します。

`counterexample` は反例、`bounded_unsat` は指定深さまで反例なし、
`incomplete` は到達可能な未定義PC/未対応WARLあり、`unknown` はタイムアウト等による判定不能です。
programコマンドは各判定に30秒の上限を指定しています。
制御Gが許可しない要求はpendingとなり、SMを継続して許可状態で切り替えます。
デモではPMP引継ぎ方式で深さ3の反例、独立テンプレート方式で深さ5まで反例なしとなります。

## 定義と限界

- [具体モデルと保護ポリシー](MODEL.md)
- [Host単独の直接データ攻撃](HOST_ONLY_ATTACKS.md)
- [基本命令の記号遷移](../models/INSTRUCTION_TRANSITIONS.md)
- [統合BMCの定義・結果の読み方](COMPOSED_BMC.md)
- [残作業](../../todo.md)

単一hart・RV64・Bareの限定命令集合を扱います。PMPとPC/GPR/メモリ/履歴は記号化し、
satp以外のCSR・trusted特権は固定です。PMは原子的な信頼操作です。
キャッシュ有効BMCでは動的satpと全体SFENCEを扱いますが、S/Uでsatp≠0のアクセスは未対応と判定します。
命令フェッチ、Sv39、invoke/再入、完全な例外処理、DMA、マルチコア、サイドチャネルは未対応です。
任意状態検証で確認するのは列挙した切替条件だけです。再開後のSMの意味的正しさ、
完全なTEE機密性、最大延期時間、任意SMの実行全体の保証はまだありません。
デモは仮想的なSM処理であり、Keystoneの脆弱性を示すものではありません。
