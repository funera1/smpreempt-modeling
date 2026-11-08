# 深さ制限のない関数CFGとIPI callback接続

## 変更点

関数本体を呼出し箇所ごとに複製する方式に加え、各関数のCFGを一度だけ保持する
`--shared-calls` を追加した。既存の展開方式はそのまま利用できる。

```sh
python3 -m smpreempt.exploration.extract_llvm \
  results/keystone-complete-ir/linked.ll \
  --abstract-model --shared-calls \
  --function destroy_enclave \
  --function sbi_ipi_process \
  --function sbi_tlb_init \
  --keystone-ipi-report results/keystone-complete-ir/ipi-connections.json \
  > results/keystone-complete-ir/shared-transitions.json
```

このモードでは `--call-depth` は使用しない。定義と整合する署名がある直接呼出しを、
到達候補の閉包が変化しなくなるまで接続する。再帰は循環となり、本体を複製しない。
`--function` を省略すると全ての定義を起点にする。

## 関数間遷移の意味

- `graph.functions`：元の関数CFGを保持し、操作・状態変数・由来の注釈を付ける。
- `calls`：呼出し箇所、継続位置、引数、戻り値、候補、未解決の理由。
- `interprocedural_links`：call_enterとcall_return。
- `callback_evidence`：関数ポインタのstoreとグローバル初期値のフィールド。

call_enterは呼出し箇所のtoken、継続位置、戻り値の束縛先を持つframeをpushする。
call_returnはstack最上位のtokenが一致する場合にだけ元の継続位置へ戻る。
再帰・複数回の呼出しではSSA値とallocationを動的frameごとに区別する。
可変長引数はframeに別途記録し、ABI実行の意味まで解釈したとは扱わない。

元のcall→継続位置の辺はIRの事実として残っているが、実行時にcalleeを迂回する辺ではない。
既知のcalleeへはcall_enterを通る。未知の効果・残余の間接対象は障壁として扱い、
外部効果の契約なしに継続できるとは仮定しない。
invoke/callbrは例外・特殊制御フローが未対応なので、通常のcall/returnに変換しない。

これは共有する遷移関係の表現であり、無限深さの実行を探索・証明したという意味ではない。

## callback候補の根拠

LLVM C APIから構造体の初期値を要素単位で抽出するようにした。
印字したIR文字列から関数名を正規表現で推測する方式ではない。

1. グローバル構造体の関数ポインタ初期値と、関数ポインタstoreを集める。
2. GEPから定数バイトoffsetを取り出す。
3. 間接callのcalleeがloadに由来する場合、そのフィールドoffsetを調べる。
4. 同じoffsetかつ署名・calling conventionが一致する関数を候補にする。
5. 各候補辺に `callee_pointer_equals_function` に相当する
   `pointer_equals_function` 条件と、初期値／storeの根拠を記録する。

**同じoffsetでも同じobjectとは限らない。** したがって、これは条件付き候補の抽出であり、
完全なalias／points-to解析ではない。各間接callには `residual_unknown: true` を残す。
候補が一つでも実行先が確定したとは扱わず、他の対象や不正なポインタの可能性も消さない。

## Keystoneで得られた接続

2026-11-07、全119 Cファイルをリンクしたgeneric構成IRを入力に実行した。
3つの起点から選択した共有グラフは91関数、3,947ノード、4,401個の関数内遷移、
594個のcall/return接続となった。呼出し深さによる打切りはない。
間接callは38箇所、条件付き候補の組合せは106件。これらを確定したcallとは数えない。

構造上は次の関数列を得た。`⇢` は条件付きcallback候補、`→` は直接呼出し。

```text
destroy_enclave
 → pmp_unset_global
 → send_and_sync_pmp_ipi
 → sbi_tlb_request
 → sbi_ipi_send_many
 ⇢ tlb_update
 ⇢ sbi_pmp_ipi_local_update
 → pmp_unset
```

IPI受信側は次の列になる。

```text
sbi_ipi_process
 ⇢ tlb_process
 ⇢ sbi_pmp_ipi_local_update
 → pmp_unset
```

これらは関数間の構造的な列。分岐条件やcallbackの条件が同時に成立する実行の証明ではない。
特に `tlb_update` の局所callbackは対象hartが現在hartと一致する分岐で実行される。

以下の根拠もJSONに記録した。

- `tlb_ops` のupdate/sync/process初期値。
- `sbi_ipi_event_create(&tlb_ops)` と、その結果を `tlb_event` に保存する命令。
- 要求objectのoffset32へ `sbi_pmp_ipi_local_update` を保存する命令（ipi.c:28）。
- 対応するoffsetから関数ポインタをloadして呼ぶ命令。
- enqueue/dequeueの呼出し位置と、両実装内のmemcpy（2箇所）。

## 別hartへの移送

`ipi-connections.json` は送信側 `tlb_update` のenqueueと、受信側
`tlb_process` / `tlb_process_count` のdequeueを、8通りの**条件付きデータ移送関係**として記録する。
8件は実行回数ではなく、静的な送受信箇所の組合せ。

必要な条件は、成功する操作、同じFIFO、同じ要求要素、サイズ、途中の不正な変更がないこと。
その条件の下で、enqueue時のpacket bytesがdequeue先へ移る、という契約を置く。
この契約は自動証明済みの事実ではない。FIFO本体のcopy-callも根拠として保存するが、
それだけでキュー不変条件・alias・ハードウェア順序・割込み配送まで証明したとはしない。
移送は通常の同期call/returnとして接続しない。

## 確認と残作業

実IR上でも、元の全辺・ノード順序の保持、関数CFGの重複なし、全接続先の存在、
復帰先とstack tokenの一致、未知の間接対象の保持、深さによる打切りなしの7項目を確認した。
結果は `results/keystone-complete-ir/shared-summary.json`。
`PYTHONPATH=. python3 results/keystone-complete-ir/validate_shared.py` で再実行できる。

全体テスト141件が成功。その後追加したinvokeの回帰テストを含め、共有CFGテスト9件も成功。
主な検査は、12段以上の呼出しと再帰、同じcalleeへの複数呼出しの復帰先、
元CFGの不変、初期値とstoreの根拠、候補の署名・offset選別、未知対象の保持、
可変長引数、キュー契約と通常辺の区別、例外経路を誤接続しないこと。

未解決事項は、callback候補の完全性、要求objectのaliasと移送の証明、イベントIDの対応、
割込み配送・進行性、残るintrinsic・asm・例外の意味、PMP書込みが実際に受理される条件。
今回はモデル抽出と条件付き接続までで、攻撃探索は実行していない。
