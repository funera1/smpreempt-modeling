# 命令・PMP・PMを接続した有界探索

## 実行

リポジトリのルートから、Z3をインストールしたPythonで実行する。

```sh
.venv/bin/python -m smpreempt.exploration.explore_system --analysis program --bound 5 --timeout-ms 10000
.venv/bin/python -m unittest -v
```

APIは `smpreempt.analysis.symbolic_system.find_counterexample(initial, program, pm, bound, exits)`。
`program` はPC→デコード済みInsn、`exits` は明示的終了PCの集合。
初期状態は既存Machineで指定する。デモ以外のPCマップも同じAPIで探索できる。
`timeout-ms` は各solver.checkの上限であり、探索全体の時間上限ではない。

## 記号状態と固定パラメータ

記号状態は次の成分を持つ。

```text
Q       = (pc, x[0..31], M, A)
P       = (pmpcfg[0..7], pmpaddr[0..7])
host    = H実行中か（falseなら開始時のCまたはSM）
status  = run / access_fault / misaligned / pm_rejected /
          exit / model_gap / unsupported / illegal_instruction
slot    = (saved_pc, saved_x[0..31], saved_P)
pending = 中断要求の保留
cache/satp/saved_satp = キャッシュまたはsatp変更を扱う場合だけ追加
```

Mは64ビットアドレス→8ビット値、Aは64ビットアドレス→Bool。
PMP設定は8ビット、アドレスレジスタは54ビットに制限された64ビット値。
`host=true` のときslotが有効。trusted状態に戻った後はslotの旧値を保持するが使用しない。
MとAはslotに保存せず、切替を越えて維持する。

初期状態は具体的に固定される。一方、途中のHost操作アドレス・書込値・操作選択、
各ステップの命令/中断/再開の選択は記号変数であり、有限アドレス候補の列挙ではない。
Hostが書いた値を再開後のLDが読み、分岐条件やPMP CSR書込値に使う経路も表現できる。

この部分モデルでは、trustedの主体・特権・satp以外のCSRは不変パラメータ。
VはBare（satp=0）、プレースホルダTLBは空に限定する。
PMはHostへ切り替えると既存具体モデルと同じPC/GPR/CSR/V初期値を構成し、
再開するとtrustedの元の値に戻す。
基本モデルのCSR/Vは固定パラメータと既知のHost初期値で表す。
追加したキャッシュ有効モデルでは動的satp、
SFENCE.VMA x0,x0、現在/キャッシュ権限の選択と生成を接続している。
初期値はsatp=0のBareに限定し、S/Uでsatp≠0のアクセスを実行しようとするとunsupportedにする。
任意のCSR/V遷移やC↔SM遷移を記号化したという意味ではない。
詳細は [PMP_SYNCHRONIZATION.md](../models/PMP_SYNCHRONIZATION.md)。

## 遷移関係

`BoundedSystem.transition` は後続状態の全成分を等式で束縛する。

| 実行中 | 選択 | 動作 |
|---|---|---|
| C/SM | STEP | 記号PCで命令を選び、9基本命令またはPMP CSRWを実行 |
| C/SM | PREEMPT | PC/GPR/PMPをslotへ保存し、Host状態とHost PMPを構成 |
| H | HOST_LD / HOST_SD | 任意のアドレス・値で既存HostActionと同じマクロ操作 |
| H | RESUME | PC/GPR/PMPをslotから復元、M/Aは維持 |

`control=PreemptionControl(...)` を渡す新経路ではWとGを分離する。
G不許可またはPMP設置不能ならSを維持してpending=Trueとし、終端にしない。
pendingでGが成立しない間はSM命令を実行できる。Gが成立した最初の境界では
STEPを禁止してPREEMPTを処理させる。ただし明示的exitでは終了し、未処理要求が残り得る。
同じ延期要求だけを繰り返す無進行辺は生成しない。再開時はpending=False。
CLIのprogramモードはこの経路を使う。

controlを省略した従来APIでは以下のチェックと拒否終端を維持する。
PREEMPTはPMPを設置できること、再開用PMPも復元できること、
指定された固定領域ポリシーと履歴検査を満たすことを条件とする。
固定領域の検査はPM.policyがある場合、Aの検査はenforce_history=Trueの場合だけ行う。
保護条件の検査には全物理バイトに対する量化式を用いる。
PMP設定の自動合成は行わず、PMに渡したテンプレートまたは現在PMPを使う。

この従来APIでの拒否やアクセス例外等は明示的な終端状態とし、その後は状態を維持する。
拒否された分岐ではHostへCPUを渡せていない。拒否後のリカバリは未実装。
通常命令を選ぶ別分岐は引き続き探索される。

明示的終了PCではSTEPを選ぶとexitになり、中断はしない。
PCマップにも終了集合にもない場所へ進むとmodel_gap。
予約されたPMP R=0,W=1を書こうとする場合は、具体モデルのUnsupportedに対応する
unsupported終端とする。未対応opcode/CSRは起動時にUnsupportedで拒否する。
このため、未対応命令を自由な遷移や正常終了として誤解しない。

## 記号的PMP

`smpreempt/model/symbolic_pmp.py` は次を定義する。

- OFF/TOR/NA4/NAPOT範囲と最小番号の重複エントリ優先。
- アクセス全体の包含、M-modeの未ロック権限迂回。
- pmpcfg0のロック済みバイト維持、予約権限の未対応判定。
- pmpaddr0..7の54ビットマスク、自身と後続locked TORによる書込禁止。
- PMがPMPを置換・復元できるかのロック判定。

範囲比較は66ビットへ拡張し、終端計算の64ビットオーバーフローを避ける。
NAPOTは末尾1ビット列を `mask=a xor (a+1)` で表現する。
空または逆順TORは一致しない。
具体モデルのPMP範囲・権限・ロックと照合しているが、全WARL/実機適合性は未証明。

## 反例条件と結果

各深さiで、任意の64ビット物理アドレスwを証人にして、

```text
host_i ∧ (A_i[w] ∨ w∈R_fixed) ∧
    (PMP_readable(P_i,w,1) ∨ PMP_writable(P_i,w,1))
```

を問う。探索はバイト単位の `R_fixed ∪ A ⊆ D_H(P)` 違反を検査する。
そのため、Host操作を実行する前の露出も検出できる。

深さ0から指定boundまで順に問うため、見つかった反例はこの遷移単位で最短。
SAT時は命令選択・Host操作を具体化し、既存Machineで再実行する。
各正常後続状態のPC/GPR/M/A/PMP/主体と、有効なslotを比較する。
固定CSR/Vは既存PMに復元させる。失敗経路では具体モデルの例外種別を確認する。

- `counterexample`: 反例と深さ・証人アドレス・replayed=true。
- `bounded_unsat`: bound以内にこの性質の反例なし。上限なしの安全証明ではない。
  `pm_rejection_reachable`で拒否への到達可能性も補足する。
  制御ありの場合は`deferral_reachable`で延期への到達可能性を補足する。
- `incomplete`: 反例は見つからなかったがmodel_gap/unsupportedへ到達する経路あり。
- `unknown`: タイムアウトなどでsolverが結論を出せなかった。

デモでは、PMP引継ぎ方式で
`LD → CSRW pmpcfg0 → preempt` の深さ3反例を得る。
独立テンプレート＋履歴検査方式では深さ5までbounded_unsat。

## 残る保証の境界

全体とは、上記の限定した遷移集合を一つのTに接続したという意味。
任意RISC-V命令、invoke/再入、Sv39、命令フェッチ、アーキテクチャ的トラップ処理、
CSR/V/特権の変更、動的な履歴解除、任意初期状態、帰納的不変条件の証明は未実装。
HostはLD/SDマクロとresumeだけであり、合法なS-mode命令列全体を包含する証明もない。
故障と従来APIの拒否の終端化により、その後の処理を探索しない。
新制御で延期後のSM継続は探索するが、全実行が有限時間で安全地点へ進むとは保証しない。
この制約を超える実機やKeystoneの安全性・可用性を結論づけない。
研究目標への接続は [RESEARCH_DIRECTION.md](RESEARCH_DIRECTION.md) を参照。
