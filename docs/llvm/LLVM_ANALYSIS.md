# LLVM抽出後の接続とKeystoneでの確認

## 今回実装したこと

アクセス制御を評価しない方針を維持し、次を追加した。

1. 定義がある通常の直接呼出しを、引数束縛→本体→戻り値束縛へ構造的に展開。
2. 直線区間でのSSA式とメモリ更新を合成。ロードが読むメモリ版と、中間のprefixを保持。
3. 二種類のbyte-clear/fillループを厳密な形の一致で認識し、処理済み長さkで要約。
4. 整数・poison・UBと、明示的なlive objectに対する限定的なメモリ実行意味論。
5. 実際のKeystone/OpenSBIからIRを生成し、リンク・抽出・展開・要約するツール。

これは全LLVMの検証器や、Keystone全体の安全性証明ではない。

## 呼出しを展開する

```sh
python3 -m smpreempt.exploration.extract_llvm examples/llvm/calls.ll \
  --function caller --expand-calls > results/llvm-calls-expanded.json
```

呼出しごとに異なるSSA/ノードIDを付ける。同じ関数を二回呼んでも戻り値やローカル変数が衝突しない。
再帰、深さ制限、定義がない関数、特殊な呼出し契約は未定義効果として保持する。
`--call-depth` は構造展開の制限で、ループ回数や実行深さの上限ではない。

`call_enter` と `call_return` には元の呼出しのIRを残す。関数・引数属性の契約成立を証明したわけではない。
byval等のABIに影響する属性や、通常でないcalling conventionは、単純な共有ポインタ束縛へ置き換えず障壁として残す。
メモリは共有するが、allocaの寿命は動的な呼出し単位で扱う必要があることを明示する。
現状は全呼出しスタックを走らせるVMではない。

## 直線区間を要約する

```sh
python3 -m smpreempt.exploration.extract_llvm examples/llvm/calls.ll \
  --function increment --summary segments > results/llvm-increment-segments.json
```

`load(entry_memory, p)` と、`load(store(entry_memory, p, v), p)` を区別する。
先行するstoreを無視して全loadを初期メモリから読むような合成はしない。
同じobjectを指す二つの引数も、後段で同一性を与えればaliasとして扱える。

分岐・基本ブロック境界・未定義効果等で区間を切る。PHIは入力元に応じた同時更新を維持する。
`prefixes` は各処理後のメモリ・SSA式を保持し、要約によって中断途中の状態を消さない。
関数呼出し/割当/寿命操作等を実行できない区間は `complete: false` と障壁を出す。
要約された出口条件について、到達可能性はまだ解かない。

## ループは回数で展開せず、処理済み長さで要約

```sh
python3 -m smpreempt.exploration.extract_llvm examples/llvm/erase.ll \
  --function erase --summary loops --prove > results/llvm-erase-summary.json
python3 -m smpreempt.exploration.extract_llvm examples/llvm/fill-pointer.ll \
  --summary loops --prove > results/llvm-fill-summary.json
```

対応しているのは以下の厳密なテンプレート。

- indexのPHIを0から1ずつ増やし、i8の各位置にゼロを書き、長さと一致すれば終了。
- pointerのPHIを1バイトずつ進め、残量のPHIを1ずつ減らし、同じbyte値を書き、残量0で終了。

どちらも長さ0の入口分岐、PHI入力、書込先、stride、値、更新式、出口条件を照合する。
余分な効果や違う形があれば `unresolved` とし、一般のループを推測でまとめない。
ループテンプレートの認識は、現在は展開前の独立した関数に対して行う。

メモリを領域先頭からのオフセットで表すと、要約は次の関係になる。

`0 <= k <= n; M_k[a] = (fill_byte if 0 <= a < k else M_initial[a])`

消去ならfill_byte=0。sbi_memset一般では任意の一定byte値なので、呼出し元でc=0であることが別に必要。
同じloopの各命令境界でも、メモリはあるkのprefixで表せる。更新はストアで起き、他のスカラー処理はメモリを変えない。
この要約はメモリへの射影であり、途中PCやCPU状態の全関係を要約するものではない。

`--prove` はZ3で初期成立・1ストア分の保存・対象外の保存・完了状態・カウンタ関係・非wrapを検査する。
kを有限回列挙しない。結果 `proved_for_template` は認識したテンプレートと明示した前提についての保証。
任意のLLVMループからの不変条件推論や、関数全体のLLVM精緻化証明ではない。

前提には、入力がdefined/non-poisonであること、長さの上限（indexの符号解釈に合わせn<2^(width-1)）、対象objectが生存しnバイトを含むこと、
pointer/index計算がwrapしないこと等がある。呼出し元でこれらが成立する検査はまだ必要。

## 限定的な実行意味論

`llvm_scalars.py` は型付き整数、符号付き/符号なし比較、cast、select、freeze、PHI入力選択、
主要なnuw/nsw/exact/nneg/disjoint等をZ3式へ変換する。
結果には値とpoison、即時UBを別々に持つ。オーバーフローした値を一律に正常値扱いせず、ゼロ除算とpoisonも分ける。
freezeは合成によって同じSSA値の式が複製されても、一回の評価内では同じ選択を共有する。

`llvm_memory.py` はobject IDを持つpointerと明示的なlive objectに対して、i8単位のメモリを実行する。
GEPのoffset、inbounds、object範囲、alignment、整数load/store、メモリに格納されたpoisonを扱う。
範囲やalignmentはLLVMの定義された操作かの条件であり、PMPやHostの権限ではない。

利用例（`increment`はexamples/llvm/calls.llの関数）:

```python
import z3
from smpreempt.frontend.llvm import extract_llvm
from smpreempt.extraction.llvm_transforms import summarize_segments
from smpreempt.model.llvm_scalars import ByteMemory, scalar
from smpreempt.model.llvm_memory import RelationEvaluator, MemoryObject, Pointer

report = extract_llvm('examples/llvm/calls.ll', functions=['increment'])
segment = summarize_segments(report)['functions'][0]['segments'][0]
memory = ByteMemory.fresh('data').store(z3.BitVecVal(0, 64), scalar(41, 64))
evaluator = RelationEvaluator.from_graph(report,
    {'f0:arg0': Pointer('data')}, {'data': MemoryObject(memory, size=8, alignment=8)})
after = evaluator.memory(segment['memory'])
# after.ub が偽という条件で、offset 0 の64bit値が42になる。
```

明示的なlittle-endian/64bit pointer・indexのprofileを検査する。scalar整数以外のload/store、
pointer/integer変換、異なるobject間のpointer比較、一般のnusw/nuw GEP、未知の式などは未対応として止める。
十分なbase alignmentの情報がなければUBと断定せず未対応とする。
メモリの初期値は入力として与える。alloca寿命、未初期化値、globalのバイト展開、全metadata/属性等は全自動化していない。
これらのAPIは部分関係の意味論であり、未定義動作を全LLVMプログラムについて検証する実行器ではない。

## 実際のvector-keystoneで確認した結果

入力:

- `/home/funera1/repo/vector-keystone`
- Keystoneコミット `01d9e19206a2d15ba5485d32d193eea381634979`（作業ツリーの変更なし）
- 既定generic RV64構成。リポジトリのriscv64_generic_defconfigが指定するOpenSBI v1.1。
- OpenSBIコミット `4489876e933d8ba0d8bc6c64bae71e295d45faac`
- Clang 20.1.2。システムへインストールせず/tmpの展開パッケージを利用。

元のKeystone checkoutは変更していない。OpenSBIと生成ファイルは/tmpまたはこのリポジトリのresultsに置く。
ビルド済みのcompile_commands.jsonはなかったため、明示的なgeneric参照構成でOpenSBI makeからCコマンドを取得した。
実際のinclude・define・ABI・最適化をそのコマンドから保持し、出力形式をLLVM IRへ変更する。
mockヘッダや切り出して書き直したenclave.cは使っていない。
ただし、ユーザーの対象ボードの配備ビルドと同一と主張するものではない。

| 段階 | 結果 |
|---|---|
| enclave.c / sbi_string.c のIR生成 | 両方成功 |
| destroy_enclave単体の抽出 | 199ノード・225遷移 |
| OpenSBIの本体をリンクした呼出し展開 | 8箇所のsbi_memsetを展開、311ノード・353遷移 |
| 展開後に残る未定義効果 | 39箇所。PMP、ロック、platform処理、intrinsic等 |
| sbi_memsetの実際の最適化済みループ | pointer/countのfillテンプレートとして認識 |
| ループのメモリprefix帰納条件 | すべてunsat（テンプレートの前提下で反例なし） |

全39箇所を無視してdestroy_enclave全体を実行・証明したわけではない。
この構成ではdestroy_enclaveの固定回数の領域ループはコンパイラが展開済みで、消去処理の可変長ループはsbi_memset内に残る。

## 再現用コマンド

Clang 20とOpenSBI v1.1 checkoutがある環境で:

```sh
python3 -m smpreempt.exploration.prepare_keystone_ir ~/repo/vector-keystone \
  --output-dir results/keystone-generic-ir \
  --generic-opensbi /path/to/opensbi-v1.1 --clang /path/to/clang-20 \
  --include-opensbi-string --run

python3 -m smpreempt.exploration.link_llvm \
  results/keystone-generic-ir/enclave.ll results/keystone-generic-ir/sbi_string.ll \
  -o results/keystone-generic-ir/linked.ll > results/keystone-generic-ir/link.json

python3 -m smpreempt.exploration.extract_llvm results/keystone-generic-ir/linked.ll \
  --function destroy_enclave --expand-calls > results/keystone-generic-ir/destroy-linked-expanded.json

python3 -m smpreempt.exploration.extract_llvm results/keystone-generic-ir/linked.ll \
  --function sbi_memset --summary loops --prove > results/keystone-generic-ir/sbi-memset-summary.json
```

capture.jsonはコミット、source hash、元のコマンド、変更した出力オプション、compiler版、IR hash、
OpenSBI版・コミット、generic configとheaderのhashを記録する。makeのコマンドとログも保存する。
リンクは異なるtarget/datalayoutや入力上書きを拒否する。

実ビルドのcompile_commands.jsonを取得できた場合は、参照構成ではなくそちらを使う。

```sh
python3 -m smpreempt.exploration.prepare_keystone_ir ~/repo/vector-keystone \
  --compile-commands /path/to/compile_commands.json --clang /path/to/clang-20 \
  --output-dir results/keystone-ir --run
```

GCCからClangへ置換する場合、元のcompiler名に埋め込まれていたtargetを失わないよう `--target` が必要。
response fileやcompiler wrapperは勝手に解釈せず、展開済みのコンパイルコマンドを要求する。

## 残る接続

- 配備対象ボードの実際のビルド条件との照合。
- 残った呼出し・atomic・volatile・アセンブリの必要な意味や契約。
- 要約の前提を呼出し元の値・管理構造から検査すること。
- 有界実行器は一部CFG・直接呼出しフレームに対応。未対応型・global初期化・属性と全体的な経路拡張。
- 必要なときに、公開前処理の完了条件、安全性・アクセス権、ELF境界を別解析として重ねること。

## 意味論の参照

[LLVM Language Reference](https://llvm.org/docs/LangRef.html) と
[GEPの説明](https://llvm.org/docs/GetElementPtr.html) を基準に部分モデルを定義している。
実際のLLVMの全意味論を置き換える保証はしない。
