# ELF命令境界でのHost直接アクセス検査

## 対象

対象関数を有界記号実行し、到達した各RISC-V命令の**実行前**に、プリエンプションを仮定する。初期PMPと管理情報の入力例は、Keystone固有の実行可能性を自動推定したものではなく、明示された入口契約である。

この第一段階で検査する機構は次の一種類。

- PMはPMPを変更せず、CPU状態はHostから隔離して保存できると仮定する。
- Hostは同一hart、SまたはU mode、Bareアドレス変換を用いる。
- 与えられた物理領域に対し、Hostが直接1 byteのR/Wを行えるかを調べる。
- `--assume-fresh-pmp`はHostのPMP判定が現在のCSR値を使うと仮定する。省略すると同期・キャッシュが未解決なので判定は`unknown`となる。

各境界`p`の、実行器が観測した状態ごとに次をZ3へ問い合わせる。

```text
PathCondition(S) AND a ∈ [region_base, region_base + region_size)
                 AND PMP_allow(S, a, 1 byte, Host_mode, R または W)
```

`region_base`と`region_size`は明示入力であり、その範囲をR/Wから保護する仕様を置く。秘密の残存や、EPMの範囲を実装から自動導出したことを意味しない。PMによるPMP再設定、Host入口の実行権限、例外・trap・復帰・再入、機密値の依存関係、PM自体の健全性は判定しない。

## 実行例

取得済みのKeystone generic研究用ELFに、[pmp_unsetの実行記録](KEYSTONE_ELF_REAL_RUN.md)と同じ初期状態を与える。`0x8000..0x8008`は説明用の保護対象で、実Keystone EPMと断定した範囲ではない。

```sh
python3 -m smpreempt.exploration.check_elf_preemption \
  results/keystone-generic-elf-patched/platform/generic/firmware/fw_jump.elf \
  --function pmp_unset --steps 150 --max-states 100 --timeout-ms 2000 \
  --pmp-json examples/elf/pmp_entry0_napot_16.json \
  --reg x2=0x90000000 --reg x10=0 \
  --mem32 0x80057a54=1 --mem32 0x80057a7c=0 \
  --mem64 0x80025110=0x80017870 --assume-mtvec-writable \
  --region-base 0x8000 --region-size 8 --assume-fresh-pmp \
  > results/keystone-generic-elf-patched/pmp_unset.entry0.preemption.json
```

この条件では、50の命令状態を探索し、2つの関数ハーネスreturnに到達した。静的な487命令境界のうち28に`abstract_counterexample`、17に`no_counterexample_within_bound`、残る442に`not_reached_within_bound`を出した。

| 命令の前のPC | 結果 | 現在のPMPを使う仮定での意味 |
|---|---|---|
| `0x80017886` | abstract_counterexample | `pmpaddr0`を0に書く前。領域内でHostのR/Wが可能なモデル状態が存在 |
| `0x8001788a` | no_counterexample_within_bound | アドレス書込み後、`pmpcfg0`書込み前。観測した状態では領域内R/Wが見つからない |
| `0x8001788e` | no_counterexample_within_bound | `pmpcfg0`書込み後、`SFENCE.VMA`実行前。同期済みを仮定した条件付き結果 |

`--assume-fresh-pmp`を省いて同条件を実行した結果は全487地点`unknown`。このモデルには古いPMP viewや実際の同期動作がないため、前述の反例候補と非反例は同期済み仮定の下でのみ解釈する。

## 状態ラベル

- `abstract_counterexample`: 観測した状態の少なくとも一つでR/W可能。アドレス・PMP値・入口からのtraceを記録する。具体再実行や脆弱性の確認はしていない。
- `no_counterexample_within_bound`: 観測済みの状態にはR/W可能なbyteが見つからず、探索・問合せの打切りがない。指定した入口と上限、モデルprofileに限る。
- `not_reached_within_bound`: そのPCを観測しなかった。全実行で到達不能という証明ではない。
- `unknown`: PMP viewの指定なし、未対応命令、未解決呼出し、solver unknown、探索打切り等。途中打切りがある場合、反例のない観測地点も`unknown`とする。

同じPCに異なる経路で到達した場合はすべて検査し、どれか一つに反例があれば`abstract_counterexample`とする。未到達地点を安全とは表示しない。

有界探索と部分ISAモデルであり、無制限の安全性・実機到達性・攻撃成立・禁止区間の保証ではない。未対応命令と関数間実行、Sailとのprofileごとの照合、PMP同期、PMの入口・復元、保護対象の導出が次の接続事項。
