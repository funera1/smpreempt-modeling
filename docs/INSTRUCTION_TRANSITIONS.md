# Bareモードの命令遷移（第1段階）

実装: `smpreempt/symbolic_instructions.py`

現在は[統合BMC](COMPOSED_BMC.md)からも呼び出す。
`access_check`コールバックにより現在の記号的PMPを参照できる。
以下は単体APIの基本定義で、PMP CSRWとPM切替は統合層が定義する。

## 状態と範囲

記号状態を `Q=(pc,x,M,A)` とする。
pcとx[0..31]は64ビット、Mは物理アドレス→8ビット値の配列、
Aは物理アドレス→Boolのアクセス履歴配列。x[0]=0とする。

固定環境 `F=(priv,CSR,V,P,c,slot)` は `environment: Machine` から与える。
ここで扱う命令はFを変更しない。FのGPR・PC・メモリ・履歴は使わない。
つまり、全Σを記号化する前段階として、環境をパラメータにした命令遷移を定義する。
命令のopcode、レジスタ番号、即値もデコード済みの固定値。
即値は既に符号拡張した整数とし、バイナリのデコードや符号化可能範囲の検証は行わない。

算術とアドレス計算はすべて64ビット、加算はmod 2^64。
以下の `write(rd,v)` はrd=0なら書き込まず、その他ならx[rd]をvに置き換える。
右辺のレジスタとPCはすべて命令実行前の値を使う。

## 成功時の更新規則

| 命令 | レジスタ更新 | pc' | メモリ・履歴 |
|---|---|---|---|
| ADD | write(rd,x[rs1]+x[rs2]) | pc+4 | 維持 |
| ADDI | write(rd,x[rs1]+imm) | pc+4 | 維持 |
| XOR | write(rd,x[rs1] xor x[rs2]) | pc+4 | 維持 |
| AND | write(rd,x[rs1] and x[rs2]) | pc+4 | 維持 |
| BEQ | 維持 | rs1とrs2の値が等しければpc+imm、それ以外はpc+4 | 維持 |
| JAL | write(rd,pc+4) | pc+imm | 維持 |
| JALR | write(rd,pc+4) | (x[rs1]+imm)のbit0をクリア | 維持 |
| LD | write(rd,load64(M,a)) | pc+4 | M維持、必要ならA更新 |
| SD | 維持 | pc+4 | store64(M,a,x[rs2])、必要ならA更新 |

LD/SDでは `a=x[rs1]+imm`。

```text
load64(M,a) = concat(M[a+7], ..., M[a])
store64(M,a,v)[a+j] = vのbit(8j+7)..bit(8j)  (j=0..7)
```

成功したC/SMのLD/SDでは `A'=Store(...Store(A,a,true)...,a+7,true)`。
HostのアクセスではAを変更しない。LD rd=0でもアクセス判定と履歴更新は行う。
命令フェッチやページウォークを履歴に入れないという既存の範囲を維持する。

**フレーム条件**: 表で更新する以外のレジスタ、物理メモリ、履歴はすべて維持する。
Fも維持する。SDの範囲外のバイトと、履歴更新の範囲外の要素も維持する。
従って、状態の更新し忘れが無制約な値になることはない。

## メモリアクセスの実行条件

現在の具体モデルに合わせ、アクセスの実効特権は通常priv。
M-modeでmstatus.MPRV=1ならデータアクセスにはMPPを使う。
実効特権がM以外かつsatp!=0なら未対応として例外を送出する。
実効特権がMなら、satpにかかわらず物理アドレスとして扱う。

8バイト整列を `aligned := (a & 7)=0`、PMP判定を`allowed`とすると、

```text
success      := aligned ∧ allowed
access_fault := aligned ∧ ¬allowed
misaligned   := ¬aligned
```

PMPは既存の範囲計算を使い、最小番号の重複エントリを選ぶ。
アクセス全体の包含を要求し、M-modeの未ロックエントリでは権限を迂回できる。
どのエントリにも一致しなければMは許可、S/Uは拒否。
PMP比較には符号なしアドレスの整数値を使い、区間終端の算術をラップさせない。
8バイト整列ならアクセス自体は64ビットアドレス空間の終端をまたがない。

`next_state` の式は成功時だけ有効。`relation(after)` は
`success ∧ after=next_state` を返す。失敗時に通常の後続状態は生成しない。
fault/misalignedの後のアーキテクチャ的トラップ状態は未実装なので、
探索器はこれらを別途扱い、単にsuccessだけを使って全遷移を網羅したと解釈してはいけない。
未対応命令（CSRW、ECALL、MRET等）は明示的にUnsupportedを送出する。

## 使用例

```python
import z3
from smpreempt.riscv_model import Insn, Machine
from smpreempt.scenarios import demo_machine
from smpreempt.symbolic_instructions import InstructionState, instruction_transition

s, _, _, _ = demo_machine()
before = InstructionState.fresh("s0")
after = InstructionState.fresh("s1")
t = instruction_transition(before, Insn("SD", rs1=10, rs2=11), Machine(s))
solver = z3.Solver()
solver.add(t.relation(after))
# 必要な初期条件・目標条件を追加して解く。
```

## 検証と限界

全9命令と別名レジスタ・x0・PCラップについて、具体値で既存Machineと照合。
任意の記号値について算術・分岐、履歴の単調性、SD範囲外のメモリ維持を検査する。
これらは実装の部分検証であり、ISA全体の適合証明ではない。

参照: RISC-V公式の
[RV64I v2.1](https://docs.riscv.org/reference/isa/unpriv/rv64.html) と
[RV32I v2.1](https://docs.riscv.org/reference/isa/unpriv/rv32.html)。
64ビットLD/SDと整数演算を参照するが、本モデルは
命令フェッチ、PC/分岐先の命令アラインメント例外、完全なCSR/特権制約を省略する。
JALRのbit0クリアだけでは32ビット命令のアラインメント条件を満たすとは限らない。

この命令関係をPCマップ・PMP更新・PM切替へ接続した定義は
[COMPOSED_BMC.md](COMPOSED_BMC.md)を参照。
