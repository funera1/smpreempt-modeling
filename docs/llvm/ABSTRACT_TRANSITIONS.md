# LLVMから抽象状態モデルへの対応付け

## 対象

`frontend/llvm.py` の命令単位CFGへ、`extraction/abstract_transitions.py` が
RISC-V操作語彙・状態変数・命令の由来・抽象化の仮定を付与します。
脆弱性探索、安全性判定、到達可能性判定は実行しません。

```sh
python3 -m smpreempt.exploration.extract_llvm examples/llvm/effects.ll \
  --abstract-model --function effects
python3 -m smpreempt.exploration.extract_llvm examples/llvm/calls.ll \
  --abstract-model --function caller --call-depth 4
```

出力schemaは `smpreempt.abstract-transitions.v1` です。
`graph` は既存の呼出し展開済みCFGで、全ノード・全辺・分岐条件・元のLLVM効果を保持します。
各辺に `abstract` を追加し、元の辺を消したり安全性条件で枝を除外したりしません。
ループは循環として残り、展開しません。

## 遷移の表現

| フィールド | 内容 |
| --- | --- |
| `abstract.operations` | 操作語彙への対応。`catalogue_id` と作用しうる状態変数、根拠、未解決の意味 |
| `abstract.may_change` | `pc`、SSA値、メモリ、CSR、同期・変換状態などの保守的な作用先 |
| `abstract.facts` | 元の辺、条件、LLVM効果、実装上の関数・命令・ノードID・debug位置 |
| `abstract.assumptions` | ポインタの扱いやasmオペランドなど、対応付けに必要な抽象化上の注記 |
| `abstract.unresolved` / `barrier` | 未対応・未証明の意味。後続辺は構造として残るが実行可能性は主張しない |
| `abstract.assembly` | inline asmの順序付き操作とLLVMオペランド束縛 |

呼出し展開で複製された命令は、元の実装ノードIDと関数を `facts.implementation` に残します。
グラフ上のIDは呼出し箇所ごとに異なるため、同じ関数への複数回の呼出しを区別できます。
ソース位置はLLVM debug情報をそのまま保持します。欠落時はnullと
`source_location_available: false` を記録し、最適化前のCとの一対一対応は仮定しません。

## 操作と状態変数

- LLVM load/storeはメモリ操作として記録し、型・幅・アドレス・値・volatile/atomic属性を元の効果に保持します。
- asmの `pmpaddr*` / `pmpcfg*` / `mseccfg` / `satp` / `mstatus` / `sstatus` 等へのCSR操作を語彙へ対応付けます。
  CSR置換・set・clearと、x0／即値による読書き抑止を区別します。
- `SFENCE.VMA` はオペランドと局所範囲を保持し、`FENCE` / `FENCE.I` も別の操作として記録します。
- LLVMのatomicとfenceはIR上の効果として記録します。AMO、LR/SC、特定のフェンス命令へのloweringは確定しません。
- メモリintrinsicは範囲操作として残します。単一の原子的なRISC-V storeとして扱いません。
- 未知のasm、制約形式、外部・間接・再帰呼出し、未確認の呼出し契約は障壁として残します。

`may_change` のRISC-V側の項目は操作カタログから導入した**宣言的な可能性**です。
実際にCSRが変化した、PMP書込みがロックで拒否されなかった、という観測事実ではありません。
LLVM load/storeから物理アドレス・PTEとしての役割・秘密の所在を推定しません。
また、LLVM SSA値を物理GPRと同一視しません。

inline asm内部は元のLLVM call辺に付随する順序付き列です。
CSR・フェンスの順序は保持しますが、`la`やalignmentの最終展開、機械命令ごとのPCは未確定です。
例外・trap経路やハードウェアの状態更新を含む完全な実行器ではありません。

## Keystoneの取得済みIRでの確認

既存のgeneric構成で取得したIRを入力に、次を実行しました。
Keystoneコミットやビルド条件は既存のcapture記録に保持され、
抽出出力自体にも入力IRのパス・SHA256とcanonical IRを保持します。

```sh
python3 -m smpreempt.exploration.link_llvm \
  results/keystone-generic-ir/enclave.ll \
  results/keystone-generic-ir/pmp.ll \
  results/keystone-generic-ir/sbi_string.ll \
  -o results/keystone-generic-ir/extraction-linked.ll

python3 -m smpreempt.exploration.extract_llvm \
  results/keystone-generic-ir/extraction-linked.ll \
  --abstract-model --function destroy_enclave --call-depth 4 \
  > results/keystone-generic-ir/abstract-transitions.json

python3 -m smpreempt.exploration.extract_llvm \
  results/keystone-generic-ir/extraction-linked.ll \
  --abstract-model --function pmp_set_keystone --function pmp_unset \
  > results/keystone-generic-ir/abstract-pmp-transitions.json
```

`destroy_enclave` は1,090ノード／1,174辺、PMP補助関数はそれぞれ
241ノード／279辺、190ノード／224辺になりました。
これらは条件分岐の全候補を保持した構造上の件数で、実際に通る経路の件数ではありません。
外部の他hart処理などは未接続なので、破棄処理から全PMP操作へ至る経路が完成したとは主張しません。
配備ボードの実行バイナリとの同一性も未確認です。

## 正確性の確認

`tests/test_abstract_transitions.py` で以下を確認します。

- 対応付け前後で全辺・ガード・効果・ブロック・ノード順序が変わらないこと（ループを含む）。
- CSR書込み→同期の順序、オペランド束縛、状態変数への対応。
- 複数回呼出しでの独立した入口・復帰と、共通する実装由来。
- debug位置の保持と欠落の明示。
- 外部・再帰・深さ制限・未知のasmを黙って無作用にしないこと。

これは抽出器の回帰・構造整合性の確認です。LLVM全体の形式的な意味保存証明や、
未対応効果を含む実装全体の安全性証明ではありません。
