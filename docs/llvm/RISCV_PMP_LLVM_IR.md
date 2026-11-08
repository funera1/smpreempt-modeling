# RISC-V PMP操作をLLVM IR命令として整理する

## 目的と境界

RISC-VのPMP操作語彙を、Keystone等の特定実装に依存せず定義し、LLVM IR上の命令へ対応付ける。
LLVM IRには標準の「PMP設定命令」はない。PMP CSRアクセスは、通常はinline assemblyまたはそれを包む関数呼出しとして現れる。

この資料でいう遷移単位は**LLVM IR命令1つ**である。したがって、1つの`call asm`に複数のRISC-V assembly文が入っていても、それを複数のLLVM遷移へ分割しない。その内部境界を調べるのは別の粒度である。

## PMP操作の抽象語彙

| 抽象操作 | RISC-V上の対象 | LLVM IRで見つかる形 | 抽象状態への作用 |
|---|---|---|---|
| PMP設定読出し | `pmpcfgN`, `pmpaddrN` | CSRを読む`call asm`、またはそのラッパーへの`call` | CSR値をSSA結果へ読む。PMP設定自体は変更しない |
| PMPアドレス更新 | `pmpaddrN` | CSRを書く`call asm`、またはラッパーへの`call` | 選択profileの書込み規則に従いCSR状態を更新 |
| PMP属性更新 | `pmpcfgN`内のR/W/X/A/L | CSRを書く`call asm`、またはラッパーへの`call` | packed CSR書込みを1遷移として扱い、対象entry群を更新 |
| 拡張セキュリティ設定 | Smepmpの`mseccfg`等 | CSRを扱う`call asm`またはラッパーへの`call` | Smepmp profileがある場合に限って更新 |
| PMP同期要求 | PMP更新後の同期操作 | asmを含む`call`。通常のLLVM `fence`とは別 | IR命令が表す同期要求を記録。完了・他hartへの波及は別契約 |
| PMP能力照会 | entry数、粒度、PA幅等 | 通常の`call`、`load`、整数演算 | profile/実装情報を取得。PMP CSR状態の書込みではない |
| 領域管理 | 領域表、bitmap、優先順位、lock等 | 通常の`load`/`store`、算術、分岐、関数呼出し | ソフトウェア管理メモリを更新。PMPハードウェア状態とは別 |
| hart間PMP更新 | IPI要求、callback、同期 | 関数呼出し、メモリアクセス、制御フロー | 要求の作成・受信・ローカル更新を別遷移として接続 |
| 通常メモリアクセス時のPMP検査 | load/store/fetchの実効アクセス判定 | LLVMの`load`/`store`等 | LLVM命令だけではPMPの実効判定結果は分からない。物理アドレス・特権・PMP profileとの接続が必要 |

R/W/X、A、Lは`pmpcfgN`の**同じpacked CSR書込みに含まれるフィールド**である。抽象的に性質を分けて記録しても、LLVM IRに別々の命令があるとは限らない。entry数やCSR配置はXLENと実装profileに依存する。

## LLVM IR命令の分類規則

### 1. inline assembly call

IR例:

```llvm
call void asm sideeffect "csrw pmpaddr0, $0; csrw pmpcfg0, $1; sfence.vma", "r,r,~{memory}"(i64 %addr, i64 %cfg)
```

これはLLVM IR上では**1つのcall命令**であり、上の例なら1つの不透明な遷移として記録する。asm文字列とconstraintから「PMP CSRに関係する」「同期命令を含む」と注釈できるが、`pmpaddr`書込み、`pmpcfg`書込み、`sfence.vma`の間にLLVM命令境界を捏造しない。

`~{memory}`はcompilerへ伝える制約であり、それだけでRISC-Vの`FENCE`やメモリ書込みを意味しない。

### 2. 定義のある関数へのcall

```llvm
%r = call i32 @configure_region(i32 %id, i8 %perm)
```

caller側ではcall命令をcall edgeとして保持する。callee本体を追う解析では、call先へ入り、calleeのIR命令を1つずつ進み、returnでcall後へ戻る。関数名だけでPMP状態が変わったと仮定しない。CSR更新または妥当な要約の根拠が必要である。

### 3. load/store、演算、分岐

これらはPMP領域表やpermission bitmapを管理している可能性があるが、命令種別だけではPMP用データだと判別できない。通常のIR命令として抽出し、構造体・global・dataflow等の根拠がある場合にだけ「PMP管理データ」と注釈する。管理表へのstoreをPMP CSR更新と同一視しない。

LLVMの`fence`も、RISC-Vの`SFENCE.VMA`を自動的に意味しない。IR opcode、inline asm、target intrinsicを別々に識別する。

## 状態遷移レコードの推奨形

各IR命令について、最低限次を保存する。

```json
{
  "transition_id": "f12:b4:i7",
  "llvm_opcode": "call",
  "effect_class": "pmp.csr_write_and_sync",
  "target_state": ["pmp_csr", "sync_request"],
  "evidence": {
    "callee_kind": "inline_asm",
    "assembly": "...",
    "constraints": "..."
  },
  "source_location": {"file": "...", "line": 123},
  "one_llvm_instruction": true,
  "architectural_atomicity": "unspecified",
  "unresolved": ["asm内部の命令間状態はこの粒度で表現しない"]
}
```

`effect_class`と`target_state`は分類結果で、`evidence`がIRから得た事実である。CSR書込みのWARL/lock結果、実効アクセス権、IPI完了等は選んだRISC-V/platform profileを別途与えない限り未解決として残す。

## 実装依存の情報をどこで使うか

抽象語彙は上表の操作群としてKeystone外で定義する。実装解析では次の関係を注釈する。

```text
ソース位置 ─ LLVM IR命令 ─ CFG edge ─ 抽象PMP操作
                       └─ call edge ─ callee内のIR命令
```

Keystoneの関数名は探索の入口やソース来歴に使えるが、語彙の定義には使わない。あるビルドにPMP処理が存在しない場合も、抽象操作カタログ自体は変わらない。

## 完全性の主張範囲

操作群の一覧はPMP関連IRを分類するための語彙であり、任意のLLVM moduleからそれらを完全自動推定できる保証ではない。inline asm、target intrinsic、外部call、link時最適化、compiler loweringで根拠の見え方が変わり得る。未知のcall/asmはunknownとして保持し、何もしない遷移へ置き換えない。

現在のKeystone generic RV64 IRでの実例と関数間IPI経路は、[抽出結果](KEYSTONE_EXTRACTION_RESULTS.md)と[共有CFG/IPI接続](SHARED_CFG_IPI.md)を参照。実装非依存のRISC-V操作カタログは[RISC-Vメモリ操作](../models/RISCV_MEMORY_OPERATIONS.md)を参照。
