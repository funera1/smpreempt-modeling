# Keystone状態遷移抽出の実行・分析

以下は3入力ファイルでの実行記録。後続の[全Cファイル一括取得](KEYSTONE_BATCH_CAPTURE.md)で、
IPI等の定義不足を解消した。callbackの実行辺などは引き続き別途接続が必要。

2026-11-07実行。対象はgeneric RV64構成で取得済みのLLVM IR。
Keystoneコミットは `01d9e19206a2d15ba5485d32d193eea381634979`。
今回は新たな実機ビルドや実機実行をせず、既存IRに対して抽出器を実行した。
脆弱性・攻撃成立の判定は行っていない。

## 入力と再現

`enclave.ll`、`pmp.ll`、`sbi_string.ll` の3入力をリンクした
`results/keystone-generic-ir/extraction-linked.ll` を使用。
リンク記録の3入力SHA256と現ファイルが一致し、enclave/PMPのIRも各capture記録のハッシュと一致した。

共通条件は `--abstract-model --call-depth 4`。
各関数のJSONと集計は `results/keystone-generic-ir/model-extraction/` に保存した。
このディレクトリは生成物としてgit管理外。

```sh
python3 -m smpreempt.exploration.extract_llvm \
  results/keystone-generic-ir/extraction-linked.ll \
  --abstract-model --function destroy_enclave --call-depth 4 \
  > results/keystone-generic-ir/model-extraction/destroy_enclave.json

# 今回の全9関数の抽出と集計・整合性チェックを再実行
PYTHONPATH=. python3 results/keystone-generic-ir/model-extraction/run_extraction.py
```

集計は同ディレクトリの `summary.json`。
詳細JSONは、各関数のcanonical IRや注釈を含むため約0.5〜13MB。

## 件数

| 起点関数 | ノード | 辺 | 循環領域 | 展開した呼出し | 障壁の辺 |
| --- | ---: | ---: | ---: | ---: | ---: |
| create_enclave | 1,204 | 1,390 | 3 | 9 | 95 |
| destroy_enclave | 1,090 | 1,174 | 8 | 41 | 99 |
| context_switch_to_enclave | 2,063 | 2,376 | 0 | 8 | 305 |
| context_switch_to_host | 2,050 | 2,365 | 0 | 8 | 310 |
| pmp_set_global | 14 | 15 | 0 | 0 | 2 |
| pmp_unset_global | 14 | 15 | 0 | 0 | 2 |
| pmp_set_keystone | 241 | 279 | 0 | 0 | 36 |
| pmp_unset | 190 | 224 | 0 | 0 | 36 |
| sbi_memset | 14 | 16 | 1 | 0 | 0 |

件数は呼出し展開後の構造で、実行回数・到達可能経路数ではない。
循環領域は命令グラフの強連結成分。ソース上の自然ループ数と同義ではない。
異なる起点のグラフは共通の実装を含むので、全行を足して固有命令数とはしない。
障壁は未知の操作だけでなく、呼出し契約の未検査や機械命令境界の未確定も含む。

## 取り出せた事実

### メモリ消去とPMP解除要求の順序

`destroy_enclave` では、LLVM上の8箇所すべてで、同じ基本ブロック内の
`sbi_memset` callの直後の命令が `pmp_unset_global` callであった。
debug位置は `sm/src/enclave.c:483` と `:486` に対応する。

`sbi_memset` は本体へ展開され、1つのstoreノードを含む循環として残る。
このため、破棄処理全体の8循環は8呼出し箇所それぞれの消去ループに対応する。
抽出されたメモリ操作はload 102、store 92で、別途LLVM memset intrinsicが1箇所残る。
store 92件は消去バイト数を意味しない。

この順序は通常CFG上の事実である。引数の領域同一性、消去完了、例外時の動作、
実際にHostへ権限が渡るタイミングを証明したものではない。

### PMP補助関数内部の操作順序

`pmp_set_keystone` と `pmp_unset` はそれぞれ、全switch候補を通算して
PMPアドレス書込み31件、PMP設定書込み31件、SFENCE.VMA 31件を持つ。
これらは代替分岐を含む静的な箇所数で、一経路の書込み回数ではない。

例えば `pmp_set_keystone` の `sm/src/pmp.c:260` に対応するasmから、次の順序を得た。

```text
la t0, 1f
csrrw t0, mtvec, t0
csrw pmpaddr0, $0
csrw pmpcfg0, $1
sfence.vma
.align 2
1:
csrw mtvec, t0
```

CSR・同期操作の順序とLLVM引数への束縛が得られる。
一方、la/alignmentの最終展開は未確定のため、このasmは障壁としても記録される。
CSR操作を認識できないという意味の障壁ではない。

### 切替処理からPMP操作への接続

`context_switch_to_enclave` と `context_switch_to_host` はそれぞれPMP補助関数を8箇所展開し、
全分岐の通算でPMPアドレス・設定書込み・SFENCE.VMAが各248件得られた（8×31）。
この入力ではsatpやmstatus等の一部CSR操作が `rK` 制約のasmとして現れ、
現抽出器はその制約に未対応である。認識可能な操作に置き換えてはいない。

## 接続できていない部分

1. **global操作からPMP補助関数への接続。**
   `pmp_set_global` / `pmp_unset_global` は `send_and_sync_pmp_ipi` で停止する。
   `destroy_enclave` にはその未解決callが8箇所残る。
   ソースの `sm/src/ipi.c` を読むと、IPI要求を組み立てて `sbi_tlb_request` へ渡し、
   callback `sbi_pmp_ipi_local_update` が `pmp_set_keystone` / `pmp_unset` を呼ぶ。
   これは今回のIRグラフで抽出できた接続ではなく、ソース確認による次の接続候補である。
   ipi.cの追加だけでなく、callbackとhart間の実行関係も明示する必要がある。
2. **未取得の補助関数・platform処理。**
   spin_lock/unlock、thread状態切替、platformフック、検証・ハッシュ等が外部callとして残る。
3. **LLVM／asmの未対応部分。**
   lifetime・overflow・ctpop intrinsic、一部aggregate操作、`rK` 制約、最終asm展開が残る。
4. **実効的なハードウェア更新。**
   CSRロック、WARL、同期後のアクセス判定、trap、実メモリへのアドレス対応は
   本抽出から計算していない。

したがって、現状は「消去→解除要求」と「PMP補助関数内の操作順序」を取り出せる。
両者を実行時の一続きの状態遷移として接続し終えてはいない。
次は `ipi.c` とOpenSBIのcallback経路の抽出、および実際に現れたasm制約の対応が優先になる。

## 正確性の確認

9関数それぞれで以下の5項目、合計45項目が一致／成立した。

- 注釈を除いた全辺・ガード・LLVM効果が既存の呼出し展開結果と一致。
- 基本ブロックの内容が一致。
- ノードの順序が一致。
- 全辺の接続先がグラフ内に存在（関数終端nullを除く）。
- 由来の関数名・LLVM命令・debug位置が入力IR抽出結果と一致。

独立した意味保存証明ではなく、既存CFGから注釈追加の段階で構造を変えていないことの検査。
さらに `python3 -m unittest tests.test_abstract_transitions -q` は9件すべて成功。
この実行ではコードの意味を変更していないため、全体テストの再実行は行っていない。

ソース位置の欠落には合成したblock_entryが多く含まれ、一部の実命令にもdebug位置がない。
例えば `destroy_enclave` の1,174辺中950辺に位置が付くが、欠落224辺のうち195辺はblock_entry。
この割合をそのまま実装命令の抽出率や正確率とは扱わない。
