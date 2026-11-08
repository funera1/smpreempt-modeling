# 具体モデルと保護ポリシー

実装は `smpreempt/model/riscv_model.py`。記号モデルの照合・反例再実行の基準として使う。
研究の目標は [RESEARCH_DIRECTION.md](RESEARCH_DIRECTION.md)、
探索の定義は [COMPOSED_BMC.md](COMPOSED_BMC.md) を参照。
現在の主対象であるHost単独攻撃は [HOST_ONLY_ATTACKS.md](HOST_ONLY_ATTACKS.md) を参照。

## 状態

`S=(E,V,P,M)`、主体付き状態は `Machine=(S,c,slot,A,pending)`。

- E: PC、RV64 GPR、M/S/U特権、選択した制御CSR。
- V: satp、プレースホルダTLB、オプションの代表PMP権限キャッシュ。実アクセスはBareのみ。
- P: 8エントリのPMP。4バイト粒度、pmpaddrは54ビット。
- M: 疎な物理バイトメモリ。未初期化バイトはゼロ。
- c: H/C/SM。PMは原子的操作として表し、通常命令を実行する主体にはしない。
- slot: 中断したE/V/Pと主体。Hostから隔離済みの抽象保存領域。
- A: C/SMの成功したLD/SD/LBU/SBでアクセスした物理バイトの集合。
- pending: 中断要求が保留されているか。SM命令実行で維持し、Host切替時に解除。

`step` はデコード済み命令を実行し、新しいSを返す。
`Machine.instruction` は主体付きの実行と履歴更新を担当する。
直接 `M.store` で行う初期化や、低水準 `step` だけの実行はAに記録しない。

## 命令とアクセス履歴

算術ADD/ADDI/XOR/AND、LD/SD/LBU/SB、BEQ/JAL/JALR、選択CSRへのCSRW、
SFENCE.VMA、簡略化したECALL/MRETを実装する。
ただしMachineでは特権変更とHost ECALLを拒否し、PM dispatchの未実装経路を通さない。
記号BMCで扱うのは基本9命令とPMP CSRWに限定する。

LD/SDは8バイト整列、リトルエンディアン。成功したC/SMのアクセスで
`A'=A ∪ [pa,pa+8)` とし、HostのアクセスではAを増やさない。
LBU/SBは1バイト操作で、対応する1バイトだけを履歴へ追加する。
LBUはゼロ拡張、SBはレジスタの下位8ビットを書き込む。Host攻撃の射影再実行にも使う。
AはMachine作成時から累積し、中断・再開や消去で解除しない。
命令フェッチとページウォークは含めない。
失敗したアクセスは例外であり、成功状態や履歴を生成しない。

## 保護条件

`ProtectionPolicy.regions` は現在のPMPと独立した信頼メタデータR_fixed。
論理的な保護対象は `R_t=R_fixed ∪ A` とする。

```text
D_H(P) = {a | not pmp_allow(P,S,a,1,R) and not pmp_allow(P,S,a,1,W)}
Host実行中の条件: R_t ⊆ D_H(P)
```

`violations` はPMP区間の端点で分割して直接R/W権限を検査する。
`Machine.history_policy()` はAを連続領域にまとめる。
これは直接隔離の条件であり、値の秘密性、正規出力、再開後の処理全体の保証ではない。
まだ触っていない領域を最初から守るならR_fixedに指定する。
デモではEPMだけを指定し、SM/PM自身と保存領域の隔離は抽象的な前提としている。

## PMとHost

`PM(template, policy, enforce_history)` は次を行う。

1. trusted E/V/Pを保存する。
2. templateがあればHost PMPとして設置し、なければ現在PMPを渡す。
3. policyがあれば固定領域、enforce_historyならAの隔離を検査する。
4. 設置・再開がPMPロックに反しないことを確認する。
5. Host Eを初期化し、VをBareにする。

再開時はE/V/Pを復元する。Hostが変更した通常メモリとAは維持する。
Vについて復元するのはsatpであり、ハードウェアキャッシュを保存・再投入しない。
`sync_pmp=True`ならPMP更新/復元後に全体同期し、Falseではキャッシュを維持する。
旧キャッシュの効果と来歴は [PMP_SYNCHRONIZATION.md](../models/PMP_SYNCHRONIZATION.md) を参照。
HostActionはレジスタ設定を省略したLD/SDマクロで、反例の再実行に使う。

PMP設定を履歴から自動合成する機能はない。隔離不能やロック制約で失敗した場合、
HostにCPUを返せたことにはならない。ポリシーを省略するPMも比較実験用に許す。

## 切替機構Wと地点制御G

`smpreempt/analysis/preemption.py` が機構と制御を分離する。

- `switchout_state` / `switchin_state`: PC/GPR/PMPの保存・Host用構成・復元というW。
  M/Aは維持する。保存領域はHostに変更されない信頼メタデータ。
- `PreemptionControl("always")`: G=true。機構だけで足りるかを調べる候補。
- `PreemptionControl("isolation")`: PMP設置/復元可能、R_fixed∪Aの全バイトのR/W禁止、
  0x1000の4バイトのHost入口X権限を要求するG。

GはPMP、A、固定領域メタデータと既知のHost入口だけを参照し、SMデータの意味は参照しない。
具体API `control.request(machine, pm)` はGが許可すればWを実行し、不許可または設置不能なら
Sを変更せずpending=Trueで返す。SM命令で進めた後、同APIで要求を再評価する。
この経路ではPMの従来の隔離チェックをバイパスし、隔離の判断をGへ移す。
`machine.preempt(pm)` の従来APIは互換性のため元のチェックを保つ。

## 表現可能状態K0からの切替検証

`check_switch(pm, control)` はSMプログラムを入力せず、任意の記号状態からW/Gを検査する。
CSR/V/特権は依然としてBare部分モデルの固定パラメータであり、全RISC-V状態の検証ではない。

K0の記号変数はPC、GPR、M、A、PMP。trusted状態、通常実行中、要求保留なしから始める。
PMPアドレス幅54ビット、予約cfgビット5/6=0、R=0/W=1を除くという形式制約だけを置く。
現在PMPが保護条件を満たすとは仮定しない。Aは任意の集合で、過去命令との整合性を課さない。
保存スロットの以前の内容は不問でWoutが上書きする。PM自身とメタデータの信頼は前提。
到達可能性は使わない。`constrain(before)` を渡せばK0を絞れるが、到達集合を含む根拠は別途必要。

検査ごとに `K0 ∧ G ∧ ¬Obligation` を解く。

| checks | 検査する条件 |
|---|---|
| install_and_restore | 元PMP→Host PMP→元PMPをロックに反せず設置できる |
| host_entry_executable | Host入口の4バイトにX権限がある |
| direct_isolation | R_fixed∪Aの任意バイトにHost R/W権限がない |
| protected_byte_integrity | Hostの任意書込後も保護バイトは変わらない |
| host_gpr_scrub | Host開始時の全GPRがゼロ |
| cpu_pmp_restore | 任意Host PC/GPR操作後も、元PC/GPR/PMPへ戻す |
| host_memory_retained | WinがHostによるメモリ変更をロールバックしない |

Hostメモリ変更は、各バイトについて書込許可があれば任意値、なければ維持という抽象操作。
完全性の検査は任意の証人バイトに射影した式で行い、命令数上限を置かない。
CPU復元の検査ではHost PC/GPRを任意値、メモリ保持の検査ではHost後のMを任意配列とする。
HostがPMPや保存スロットやAを変更する操作は含めない。invoke/CSR変更も対象外。

各checksのsatはその条件の反例、unsatはその条件の成立、unknownは判定不能。
satのwitnessはPMPと一つの履歴所属などの抜粋で、実命令で到達できる反例を意味しない。
domain/admission/denialでK0・許可状態・不許可状態の存在も別々に調べる。

- `valid_for_K0_obligations`: 許可状態が存在し、全検査の違反式がunsat。
- `counterexample`: 一つ以上の違反式がsat。この候補W/Gの失敗であり、PM一般の不可能性ではない。
- `empty_domain`: 入力制約が矛盾。
- `no_admitted_state`: K0は存在するがGが全状態拒否。
- `unknown`: 必要な検査が未決着。

constrainを指定した場合はstate_set=constrained_K0と表示し、その集合だけの結論となる。
G=isolationの十分性はGに含めた条件に対するもの。最弱のGや最適なWを合成したわけではない。
Host入口X権限は最小限のチェックで、命令内容や実際のHost進行を保証しない。
全TEEの非干渉性、共有入力の意味的整合性、有限時間での要求処理も未証明。

## 仕様との対応・未対応

PMPは最小番号の重複エントリを優先し、アクセス全体を覆わなければ拒否する。
locked TORは直前のpmpaddrもロックする。予約R=0,W=1のWARL処理はUnsupported。
参照は [RISC-V Machine-Level ISA](https://docs.riscv.org/reference/isa/priv/machine.html)。
Sailとの完全な差分検証やISA適合証明は未実施。

命令フェッチ、分岐先アラインメント例外、Sv39、全CSR制約、実トラップ副作用、
PMA、FPU/vector、DMA、マルチhart、メモリ順序、キャッシュ側チャネルは扱わない。
PM自身の命令列、任意地点でM-modeを止めるハードウェア、動的所有権/履歴解除、
invoke/再入も未実装。今後の契約・一般化は [todo.md](../../todo.md) に残す。
