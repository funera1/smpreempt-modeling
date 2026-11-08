# LLVM IRからの状態遷移抽出

## 目的と現在の範囲

アクセス権や安全性判定を置かず、実装の演算・メモリ操作・制御フローを構造化する。
入力はLLVM IRの `.ll` またはbitcode `.bc`。LLVM公式のパーサ・検証器をC API経由で使う。
テキストを正規表現で解析したり、objdumpの表示を再解析する方式ではない。

現在の出力は **LLVMの意味を保持した構造的な遷移グラフ** であり、独立したLLVM実行器や検証器ではない。
標準のgraph抽出ではZ3、到達可能性解析、経路列挙、ループ展開、PMP判定、Host操作、秘密の仕様は使わない。
ELF/BMCとは別の入口とし、既存の安全性検査は変更しない。
後続機能として呼出し展開、区間要約、ループテンプレートの帰納検査、限定的な実行意味論を追加した。
詳細と実際のKeystoneでの結果は [LLVM_ANALYSIS.md](LLVM_ANALYSIS.md) を参照。

## 実行

PythonとlibLLVM 18または20が必要。Pythonパッケージの追加は不要。Clangやllvm-disがなくても、既存IRを読める。
libLLVM 20.1.2と18.1.3で動作を確認した。その後、Clang 20.1.2を/tmpに取得し、小さなC例と実際のKeystoneの翻訳単位からの生成も確認した。

```sh
python3 -m smpreempt.exploration.extract_llvm examples/llvm/erase.ll \
  --function erase > results/llvm-erase.json

python3 -m smpreempt.exploration.extract_llvm examples/llvm/effects.ll \
  --function effects > results/llvm-effects.json
```

`--function` は繰返し指定可能。省略時は全関数を抽出する。シンボル索引とcanonical IRはモジュール全体を保持する。

ライブラリを自動発見できない場合:

```sh
python3 -m smpreempt.exploration.extract_llvm input.ll \
  --llvm-library /path/to/libLLVM.so
# または SMPREEMPT_LIBLLVM を設定する
```

CLIは読取・抽出だけを行い、入力を実行・最適化・上書きしない。
構文エラーやSSA不整合はLLVMの検証で拒否し、CLIの終了コード2として報告する。
`.bc` のバージョン互換性は読み込むLLVMに従う。生成元と読取側のLLVM版を合わせるのが基本。

## C/Keystoneから入力を用意する

Clangがある環境なら、例えば以下でCからIRを作れる。

```sh
clang --target=riscv64-unknown-elf -O0 -g -S -emit-llvm \
  examples/llvm/memory.c -o /tmp/memory.ll
python3 -m smpreempt.exploration.extract_llvm /tmp/memory.ll
```

これは単独の小例向け。Keystoneでは実際のビルドのinclude、define、ABI、target、最適化条件を維持して、対象translation unitのIRを取得する。
最適化で消去ループがmemsetに変わる場合もあるので、IRの段階とオプションを記録する。
最終バイナリと同じ命令境界を表すものではない。リンク・アセンブリ・コンパイラ後段との対応は別途必要。
複数translation unitは必要に応じて互換版のllvm-link等で結合する。抽出器自体はCビルドやリンクを行わない。

`erase.ll` と `effects.ll` は手書きのIRフィクスチャであり、`memory.c` をコンパイルした成果物という主張はしない。

## 状態と遷移の表現

状態の概念は次のとおり。

- `pc`: 命令ノードID。
- `values`: 一回の関数呼出し内の、型付きSSA値の束縛。
- `memory`: 抽象メモリ。load/storeに型・サイズ・アラインメント・アドレスを付ける。
- `predecessor_block`: PHIの入力選択に使う直前の基本ブロック。

同じ関数の再帰呼出しなど、複数の呼出しフレームはまだ実装しない。
IDは `f0:b1:i2` のように関数・ブロック・命令位置から作り、LLVM内部のポインタやユーザーの命名に依存させない。
関数引数は `f0:arg0`、globalは `g0` のような参照になる。

遷移はJSONで `source`、`target`、`guard`、`effect` を持つ。
例えば分岐の真側は次の形になる（説明用に一部省略）。

```json
{
  "source": "f0:b0:i1",
  "target": "f0:b2:entry",
  "guard": {"kind": "reference", "id": "f0:b0:i0"},
  "effect": {"kind": "control"},
  "predecessor_block": "f0:b0"
}
```

普通の演算は `assign` と型付きの演算式、ロードは `load`、ストアは `store` として出す。
`ret` は戻り値を持つ終端、`unreachable` は定義された実行ではないことを明記した終端にする。
各命令にLLVMのcanonicalな命令文字列を保持し、デバッグ位置があればファイル・行・列も付ける。
モジュール全体のcanonical IRも保存するので、属性グループ、メタデータ、型定義等への参照を失わない。

### 分岐とループ

条件分岐は条件とその否定による二本の辺。switchは各caseとの等値条件と、それら以外のdefault条件。
分岐条件が成立するかは、この抽出では解かない。

ループは戻り辺を持つグラフとして保持し、回数の上限を置かない。
`cyclic_regions` はCFG上の強連結成分を出す。実行可能性や終了性、自然ループのヘッダを証明した情報ではない。
基本ブロックを原子的にするわけではなく、命令ごとのノードと遷移を残す。

### PHI

複数PHIは一つの合成されたブロック入口遷移 `parallel_phi` で、直前のブロックに応じて同時に更新する。
例えばループで `%x <- %y` と `%y <- %x` を行うとき、逐次代入として値を壊さない。
PHI命令自体もブロックの `phis` に元のIRと入力元を保持する。
これはLLVM PHIの意味を表すための入口であり、実機の中断命令に対応するものではない。

## メモリ操作

普通のload/storeは、操作の方向、アドレス、値、値の型、サイズ、alignmentを出す。
アクセス可能か、値が公開可能か、用途に妥当かは判定しない。

GEPはbase、source type、index列、inbounds、オフセット項を保持する。
明示的なmodule datalayoutがあれば、LLVM TargetDataを使って配列要素のstride、構造体フィールドのpaddingを含むoffsetを取得する。
例えば `{ i8, i64, [4 x i16] }` の配列部分へのアクセスは、先頭要素の大きさ、field offset、i16のstrideを分けて出す。
これは整数として無制限に足し合わせたポインタ式ではない。実行器を作る際はLLVMのindex幅・符号拡張・inboundsの意味に従う必要がある。

datalayoutがなければバイト数やオフセットは `null` にし、ホストマシンのレイアウトを勝手に使わない。
allocaは要素型、個数、配置サイズ、alignmentと新しい割当先を表す。スタック上限や割当失敗は評価しない。
globalの初期値は型付き値として保持するが、ロード可能なバイト配列への初期化は未実装。

## 不明な効果を隠さない

以下は `opaque_effect` とし、意味の追加が必要な障壁として出す。

- 外部・内部の関数呼出し、間接呼出し、invoke/callbr。
- memset/memcpy等のメモリintrinsic。
- インラインアセンブリ。文字列、制約、sideeffect、引数を保持する。
- atomic/volatileアクセス、fence、その他の未対応命令。

後続位置は構造として残すが、`requires_semantics: true` とし、メモリ不変や原子的な関数実行を仮定しない。
「その呼出しの先へ進める」モデルにするには、関数本体の展開または妥当な要約が必要。
特にmemsetを原子的な全消去として扱うことはしない。
invoke等の後続条件は例外の意味を未定義として `opaque_successor_condition` にする。

出力statusの `extracted` は構造抽出完了、`extracted_with_opaque_effects` は未定義効果を含む抽出完了。
どちらも安全性や全状態の到達可能性を保証する結果ではない。

## LLVM特有の意味を残す

整数幅、符号付き/符号なし比較、nuw/nsw/exact等の属性、undef/poison、GEPの型・inboundsを保持する。
未構造化のconstant expressionは元のIRと `requires_semantics` を残す。
canonical IRに存在するその他の属性も、将来の実行器で勝手に無視してよいという意味ではない。
抽出器自体はそれらを実行しない。別層の限定的な実行意味論では整数フラグ・poison・UB等を扱うが、全LLVM命令・属性・metadataの実行器ではない。
とくにpoisonや未定義動作を単なるビットベクトル値へ置換すると、LLVMと違う遷移になるため注意が必要。

## 検証

```sh
python3 -m unittest tests.test_llvm -v
```

ループの保持、分岐とswitch、PHI同時更新、構造体paddingと配列stride、整数幅・flags、opaque effect、
不正IRの拒否、.ll/.bcの抽出一致、LLVM 18/20での入力、CLIを検査する。
Keystoneのgeneric構成での入力・呼出し展開も確認済み。対象ボードの配備バイナリとの一致は未検査。

## 次の接続

1. 固定したKeystoneビルドから対象関数のIRを取得する。
2. 必要な呼出しを展開するか、途中状態を残す要約を追加する。
3. メモリ操作に関する基本ブロックやループの要約をグラフから作る。
4. 必要になった段階で型・ポインタ・poisonを含む実行意味論と接続する。
5. 公開前処理・検証・使用の仕様、アクセス制御、ELF命令境界との対応を別解析として重ねる。

## 参照

- [LLVM C API: IR Reader](https://llvm.org/doxygen/group__LLVMCCoreIRReader.html)
- [LLVM C API: Instructions](https://llvm.org/doxygen/group__LLVMCCoreValueInstruction.html)
- [LLVM Language Reference](https://llvm.org/docs/LangRef.html)
