# RISC-V SM preemption verification

RISC-Vセキュアモニタの安全なプリエンプションを検討する研究用モデルです。
目標は、共通PMの切替操作と中断可能条件を導き、その制約を減らすSM構造を考えることです。
研究の前提・方針は [docs/RESEARCH_DIRECTION.md](docs/RESEARCH_DIRECTION.md) を参照してください。
まず表現可能な中断状態に対してPM操作と中断条件を設計し、対応コストや制限が大きい場合に
到達可能性の情報で対象を絞ります。現在は、まず中断後のHostだけで完結する直接データ攻撃を対象にします。

## 構成

```text
smpreempt/
  riscv_model.py             # 具体モデル: 命令、PMP、PM、履歴、Host操作
  preemption.py              # 切替W・中断条件G・任意状態の検証
  host_attacks.py            # 中断後のHost単独の読取・書換え攻撃
  symbolic_instructions.py   # 記号的な基本命令・メモリ操作
  symbolic_pmp.py            # 記号的なPMP判定・CSR更新
  symbolic_system.py         # 遷移の接続、BMC、反例の具体再実行
  scenarios.py               # デモとテストで共有する仮想SMシナリオ
  exploration/
    explore_system.py        # 探索の実行入口
tests/                      # 具体・記号モデルの照合と回帰テスト
docs/                       # 定義と研究方針
results/                    # 生成結果
todo.md                     # 残作業
```

## 実行

リポジトリのルートから実行します。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-smt.txt
.venv/bin/python -m smpreempt.exploration.explore_system --analysis attacks
.venv/bin/python -m unittest -v
```

結果を保存する場合:

```sh
.venv/bin/python -m smpreempt.exploration.explore_system --analysis attacks > results/attacks.json
```

Z3なしでも `python3 -m unittest -v` で具体モデルのテストを実行できます。
記号モデルのテストはその場合skipされます。
旧列挙・BFS・Host窓専用の探索は統合BMCへ集約しました。

## 現在の探索

既定の `--analysis attacks` は、任意の中断状態からWoutでHostへ渡し、
Hostの読取・書換えだけで保護対象へのアクセスが成立するかを調べます。
G・再開・新規呼出しを使わず、PMP設置不能やHost入口の権限不足は攻撃と分けて報告します。
反例にはHostのLBU/SBと、読取値または変更前後の値を出し、具体モデルで対象バイトを再実行します。
PMPとRがHost実行中に不変なBare通常データ操作に限定し、命令数の上限は置きません。
定義と結果の読み方は [HOST_ONLY_ATTACKS.md](docs/HOST_ONLY_ATTACKS.md) を参照してください。

`--analysis states` は従来の補助的なW/G検証です。
SM命令列や初期値を固定せず、記号状態K0から切替を検査します。
固定PMPテンプレートという機構Wに対し、無条件のG（always）と、隔離等を確認するG（isolation）を比較します。
設置/復元可能性、Host入口のX権限、直接隔離、保護バイトの完全性、GPR初期化、CPU/PMP復元を個別に検証します。
各checksのsatはその条件の反例、unsatは定義したK0に対するその条件の成立です。
許可状態の存在も調べ、全状態拒否を成功と扱いません。
K0と保証の範囲は [MODEL.md](docs/MODEL.md) を参照してください。

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

- [具体モデルと保護ポリシー](docs/MODEL.md)
- [Host単独の直接データ攻撃](docs/HOST_ONLY_ATTACKS.md)
- [基本命令の記号遷移](docs/INSTRUCTION_TRANSITIONS.md)
- [統合BMCの定義・結果の読み方](docs/COMPOSED_BMC.md)
- [残作業](todo.md)

単一hart・RV64・Bareの限定命令集合を扱います。PMPとPC/GPR/メモリ/履歴は記号化し、
CSR・アドレス変換・trusted特権は固定です。PMは原子的な信頼操作です。
命令フェッチ、Sv39、invoke/再入、完全な例外処理、DMA、マルチコア、サイドチャネルは未対応です。
任意状態検証で確認するのは列挙した切替条件だけです。再開後のSMの意味的正しさ、
完全なTEE機密性、最大延期時間、任意SMの実行全体の保証はまだありません。
デモは仮想的なSM処理であり、Keystoneの脆弱性を示すものではありません。
