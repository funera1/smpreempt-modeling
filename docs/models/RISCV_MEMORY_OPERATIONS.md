# RISC-Vのメモリ操作を状態遷移として表す

## 目的

Keystone等の特定実装によらず、メモリ内容・保護設定・アドレス変換・同期・実効アクセス文脈に関係する操作を列挙する。
その共通表現へ、LLVM/ELFから取り出した実装の操作を後で接続する。

RISC-Vに一般的な「この領域を機密にする／機密でなくする」という一命令があるとは仮定しない。
所有権移譲、初期化、検証、消去は、通常の命令と管理情報更新を組み合わせたソフトウェアの処理である。
今回は操作の状態遷移表現が対象で、保護対象・公開可能性・アクセス履歴・攻撃成立条件を導入しない。

## 実装と使い方

- `smpreempt/model/riscv_memory_operations.py`: 22操作群の宣言的な遷移テンプレート、デコード済み命令の正規化。
- `smpreempt/exploration/riscv_memory_operations.py`: カタログ／個別操作／命令列のJSON出力。
- `examples/riscv-memory-ops/`: PMP更新とPTE更新の入力例。

```sh
# 操作群の一覧と遷移テンプレート
python3 -m smpreempt.exploration.riscv_memory_operations \
  > results/riscv-memory-operations.json

# PMP設定書込み一種類の関係
python3 -m smpreempt.exploration.riscv_memory_operations --operation pmp.config.write

# 命令列を操作列へ正規化し、命令間の境界を保持
python3 -m smpreempt.exploration.riscv_memory_operations \
  --input examples/riscv-memory-ops/pmp-update.json
```

これは完全なISA実行器ではない。テンプレート内の `PMPConfigWritePolicy` 等は名前を持つ未実装の意味関数であり、
勝手な値を返す関数や、何もしない関数として扱わない。
profile依存の意味論を埋める箇所を明示した、機械可読なモデルの語彙である。
既存の8-entry PMP/BMC部分モデルへ自動接続したという主張もしない。

## 操作群

| 分類 | 操作ID | 対象 |
|---|---|---|
| 内容 | memory.load | integer/FP/vector/guest load群 |
| 内容 | memory.store | Store群。消去・初期化・コピーの構成要素 |
| 内容 | memory.amo | AMO/CAS、順序指定 |
| 内容 | memory.lrsc | 予約と条件付き書込み |
| 制御 | csr.read | 書込みが抑止されたCSR読取り |
| 保護 | pmp.address.write | pmpaddrN |
| 保護 | pmp.config.write | pmpcfgNのR/W/X・A・Lを含む一回の書込み |
| 保護 | pmp.security.write | Smepmpのmseccfg |
| 変換 | translation.satp.write | satpのMODE/ASID/PPN |
| 変換 | translation.pte.write | PTEへのStore/AMO/SCという文脈付き操作 |
| 同期 | translation.sfence.vma | hart・アドレス・ASID範囲付きの変換同期 |
| 実効文脈 | privilege.mstatus.write | MPRV/MPP等を含むCSR操作 |
| 実効文脈 | privilege.sstatus.write | SUM/MXR等とmstatusのalias関係 |
| 実効文脈 | privilege.return | MRET/SRETによる特権復帰 |
| 順序 | ordering.fence | データ／I/O等のメモリ順序 |
| 順序 | ordering.fence.i | ローカル命令フェッチの同期 |
| 属性 | attributes.environment.write | menvcfg等。PBMTEや拡張制御 |
| 属性 | attributes.platform.change | プラットフォーム固有のPMA等の変更 |
| 内容・拡張 | cache.zero | ZicbozのCBO.ZERO |
| 可視性・拡張 | cache.management | Zicbomのclean/flush/inval |
| 仮想化 | translation.guest.root.write | H拡張のvsatp/hgatp |
| 仮想化 | translation.hfence | H拡張のHFENCE.VVMA/GVMA |

これは関連する操作群のスコープであり、全拡張・全opcodeの網羅宣言ではない。
FP/vector/guestアクセス等はカタログの対象だが、現在のデコード済み入力の正規化は主要な整数・CSR・フェンス等の部分集合。
未対応のopcodeは未知の効果として残す。
DMA/IOMMU/debugや副チャネル、trap handlerの命令列は別のモデルが必要。

## 状態の分割

概念上の状態は、位置・レジスタ・メモリ・CSR・特権・変換view・PMP view・順序・予約・platformに分ける。
CSRの設定値と、ハードウェアが利用してよい変換／権限情報は分ける。
viewは「自由に作れる権限」ではなく、選んだprofileで許される過去の観測等に由来する状態を表す場所である。

各テンプレートは次を持つ。

- `requires`: ISA拡張・特権等の必要条件。
- `parameters`: レジスタ値・幅・アドレス・hart・実装条件。
- `normal_relation`: 入力と出力を結ぶ関係。
- `may_change` / `preserves`: 更新対象と保存する状態。
- 非正常結果・制約・一次資料への参照。

実行profileではXLEN、物理アドレス幅、PMP数・粒度、WARL、VM実装、拡張、hart構成を固定する必要がある。
例えばRV64でアクセスできるpmpcfg番号、ロック状態、未実装CSR、TVM等を無視して正常遷移を選んではいけない。

## PMP操作の関係の具体形

Smepmpなしの基本PMPなら、pmpaddr_iへの書込みは概念的に、

```
blocked = 自身のL
       または（次のエントリがTORで、そのLが立っている）
pmpaddr_i' = blocked ? pmpaddr_i : WARL_addr(requested)
M' = M
```

となる。pmpaddr_iの変更は、次のTORエントリの下限も変える可能性がある。

pmpcfgへの一回の書込みは、格納する複数エントリの各byteについて、

```
cfg_i' = cfg_i.L ? cfg_i : WARL_cfg(requested_byte_i)
```

という関係を持つ。ただしSmepmpでは追加の規則が必要。
ロックによって無視される書込みは、単純にillegal instructionという意味ではない。
R/W/X・A・Lの同時更新、エントリの優先順位、TORの隣接関係を残す。

ここから現在の実効権限まで求めるには、同期・キャッシュviewの意味論も必要である。
PMP設定を書いたら自動的にすべての古い許可が消える、とは表現しない。

## CSR一命令の境界を壊さない

CSRRW/CSRRS/CSRRCと即値版を共通形式へ正規化する。例えば、

```json
{"opcode": "CSRRW", "csr": "pmpcfg0", "rd": 5, "rs1": 5}
```

は、「書込み値は変更前のx5」「x5への戻り値は変更前のCSR」という一つの命令遷移になる。
read→write→rd代入の三つの中断可能な機械命令へ分解しない。

- CSRRWでrd=x0なら読取りを抑止するが、書込みは行う。
- CSRRS/CSRRCでrs1=x0なら書込みを抑止する。
- 非x0レジスタの値が偶然0でも、書込み抑止とは同一視しない。
- 即値版ではzimm=0の規則を使う。
- CSRW/CSRS/CSRC/CSRR等のaliasも正規化する。

CSR番号と名前を受け付ける。数値アドレス・レジスタ番号・即値の形式は検査するが、全profileの合法性判定はまだ行わない。

## 命令列の出力

入力例は次の四命令。

```
CSRRW pmpaddr0, x0, x5
CSRRS pmpcfg0, x7, x0
CSRRW pmpcfg0, x0, x6
SFENCE.VMA x0, x0
```

ここでの並びはデコード済みフィールドの説明用表記。実際のアセンブリ構文は入力JSONを参照。
出力は、

```
s0 -- pmp.address.write --> s1
s1 -- csr.read ----------> s2
s2 -- pmp.config.write --> s3
s3 -- sfence.vma --------> s4
```

という順序になる。s1/s2/s3等を保持し、後でその時点の状態を検討できる。
「s1で実際に中断できるか」は割込み・PMモデルとの接続事項であり、この出力だけでは断定しない。

## PTE・属性・フェンスの区別

Store命令だけからPTEへの書込みかどうかは分からない。
`memory_role: pte` と `role_evidence` を実装解析等から与えた場合だけ、同じ書込みをPTE更新として分類する。
Storeを二回適用するのではない。SCなら成功時に限った書込みであることも維持する。
SvpbmtのPBMT変更はPTE更新のfacetで、独立した追加メモリ書込みにはしない。

PMAを変更する普遍的なCSRや命令は仮定しない。変更可能なplatformなら、その固有インターフェースの意味を与える。
`SFENCE.VMA`、`FENCE`、`FENCE.I`、cache管理は別の操作で、どれも普通のメモリの消去とは同一視しない。
SUM/MXR変更にも一律にフェンス待ち状態を導入しない。

SFENCE.VMAはrs1/rs2のレジスタ番号も保持する。
x0による全範囲指定と、非x0レジスタに値0を入れた指定では対象範囲の意味が異なる。
単一hartの同期を他hartの同期完了に読み替えない。

## 次の実装

1. この語彙へLLVM/ELF/アセンブリの操作を結びつけ、元の位置を保持する。
2. まず基本PMPと全体SFENCEのprofileについて、未実装の意味関数を具体的な関係にする。
3. trap/無視される書込み/未対応WARL等を分け、正常遷移だけを無条件に選ばない。
4. 必要な変換・拡張・platformのprofileを追加する。
5. 抽出後の別解析として、公開前処理の完了等と組み合わせる。

今は1への共通語彙と操作列の表現を作った段階で、一覧全体のISA実行や攻撃判定まで実装済みとはしない。

## 参照資料

- [RISC-V Machine-Level ISA / PMP](https://docs.riscv.org/reference/isa/v20260120/priv/machine.html)
- [Zicsr](https://docs.riscv.org/reference/isa/v20260120/unpriv/zicsr.html)
- [Supervisor ISA](https://docs.riscv.org/reference/isa/priv/supervisor.html)
- [Smepmp](https://docs.riscv.org/reference/isa/v20260120/priv/smepmp.html)
- [Svpbmt](https://docs.riscv.org/reference/isa/v20240411/priv/svpbmt.html)
- [CMO](https://docs.riscv.org/reference/isa/unpriv/cmo.html)
- [H extension](https://docs.riscv.org/reference/isa/priv/hypervisor)

主な参照はv20260120。一部は各リンク先の版を明記した補足資料であり、全拡張を一つの完成済みprofileとして統合してはいない。
