# 有界LLVM状態遷移の実行

`extract_llvm`が作る関数CFGを、明示したステップ数・状態数の範囲で実行する試作です。分岐条件はZ3の経路条件として保持し、各命令辺がSSA値・byte memory・PMP/CSR状態を更新します。

```sh
python3 -m smpreempt.exploration.extract_llvm \
  examples/llvm/erase.ll --function erase \
  --execute-bounded 30 --max-states 100
```

Keystone取得済みIRでは、たとえばPMP初期化関数を次のように追えます。

```sh
python3 -m smpreempt.exploration.extract_llvm \
  results/keystone-complete-ir/linked.ll --function pmp_init \
  --execute-bounded 300 --max-states 10 > /tmp/pmp-init.json
```

この入力では1経路が87 CFG辺でreturnし、8エントリ分の`pmpaddrN`、`pmpcfg0`書込みと`SFENCE.VMA`を抽出しました。イベントにはasmを含むLLVMノードIDと、取得IRに含まれるCソース位置を付けます。`machine_events`がCSR/同期操作、`pmp`が終了時点の記号PMP状態、`trace`が関数呼出しを含むCFG辺です。`path_condition`はその実行経路に必要な条件です。

## 実装済みの遷移

- 整数演算・比較・select・cast、PHI同時更新、GEP、通常の整数およびポインタload/store、分岐、return。
- 関数本体がある直接呼出し。呼出しフレームを積み、return時に呼出し元へ戻る。再帰・深さは`--runtime-call-depth`で制限。
- `llvm.memset`の非volatile形式。byte arrayを記号更新し、no-wrap条件を経路条件へ追加。
- `llvm.lifetime.start/end`はメモリを変更しないイベントとして記録。
- 対応するRISC-V inline asm内のCSR read/write/set/clear、`pmpaddr0..7`、RV64 `pmpcfg0`、`SFENCE.VMA`。
- `FENCE`/`FENCE.I`は順序イベントとして、`SFENCE.VMA`は別の翻訳同期イベントとして記録。
- Keystone/OpenSBIの` sbi_printf`だけは外部ログ要約を適用し、そのRAM/PMP効果をモデル化しない仮定をイベントに残す。

RV64の8-entry base-PMPモデルを使い、PMP書込みは既存モデルのlocked/WARL条件で状態更新します。これはKeystoneのPMP設定と実行順を追うための意味論であり、実機の全CSR/PMP/Smepmp仕様を実装したものではありません。

## 出力の読み方と限界

`paths`の各要素が終了・上限到達・未対応効果で停止した経路です。`memory_events`はload/store/memsetの操作列です。`source_locations`は当該経路のCFGノードIDから関数名とソース位置への対応です。`--show-values`を付けると終了SSA値を追加します。

メモリは64-bitアドレスの単一記号byte arrayです。LLVM object境界、alias、alignment、poison byte、完全なallocation lifetimeは扱いません。集成体のロード、atomic/volatile、未知asm、未要約の外部/間接呼出しはその経路を`stopped`にします。未知の関数を勝手にno-opとは扱いません。ループは指定したCFG辺上限まで反復し、全実行の完備探索ではありません。

PMP CSR更新からHostの実効アクセス権、hart間IPIの完了、キャッシュ済み変換、命令フェッチ、割込み/例外動作は導きません。したがって、ここで得られるのは実装由来の部分的な状態遷移列であり、攻撃可能性や安全性の判定ではありません。
