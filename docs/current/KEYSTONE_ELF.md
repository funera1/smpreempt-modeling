# 実装ELFから状態遷移を取り出す

## 実装した範囲

指定関数の機械命令一覧とPMP関連の分類は、LLVM MCのC APIを使う別の入口から取得できる。

```sh
python3 -m smpreempt.exploration.inspect_elf_pmp /path/to/sm-containing.elf \
  --function pmp_unset > /tmp/pmp-unset-inventory.json
```

`instructions`にはPC、機械語、命令長、LLVMの逆アセンブル表示、制御フロー候補、PMP CSRまたは`SFENCE.VMA`の分類を出す。CSRのread/write抑止、register番号、即値、CSR番号は機械語のフィールドから抽出する。`execution_model_status`は既存の記号実行モデルへの命令対応の有無であり、LLVMがデコードできたことと区別する。ELF hash、関数の範囲、LLVM library、target featuresも記録する。

`--features`には実際のビルドに対応するRISC-V機能を指定する。既定は`+m,+a,+f,+d,+c,+zicsr,+zifencei`。libLLVM 20または18を自動検出し、`--llvm-library`で指定もできる。関数はサイズ付きの定義済みELFシンボルでなければならない。
`--build-metadata build.json`を指定すると、外部で用意したビルド情報とそのSHA-256を結果へ記録できる。省略した場合は`null`となり、ELFからコミットやビルド条件を推測しない。

小さな合成ELFで試す場合:

```sh
python3 -m examples.elf.build_pmp_fixture /tmp/smpreempt-pmp-demo.elf
python3 -m smpreempt.exploration.inspect_elf_pmp /tmp/smpreempt-pmp-demo.elf \
  --function pmp_demo > /tmp/smpreempt-pmp-demo.json
```

LLVMのC APIはMCInstの構造化operandを公開しないため、現状は表示文字列を解析せず、CSR・`SFENCE.VMA`と一部の制御フローについてのみ機械語フィールドを構造化している。それ以外のopcode/operandは`null`として表示文字列を残す。C++ MCInst backendは未実装。正常経路の後続候補であり、例外・非同期割込み、間接分岐先、実際の到達可能性は未解決。PMP書込みの有効性・状態更新・安全性判定もこの一覧には含まれない。

### PMP命令の有界記号実行

上の合成ELFについて、PMP CSRの前後の式を追う入口:

```sh
python3 -m smpreempt.exploration.step_elf_pmp /tmp/smpreempt-pmp-demo.elf \
  --function pmp_demo --steps 10 --reg x11=0x123 > /tmp/smpreempt-pmp-steps.json
```

LLVM MCで命令として認識できることを確認し、実行意味論を持つ部分集合だけをZ3で進める。PMP CSRに対するCSR read/write/set/clearと即値形式、RV64 `pmpcfg0`/`pmpcfg2`、`pmpaddr0..15`、一部の整数演算・load/store・条件分岐・直接ジャンプ、return、`SFENCE.VMA`を扱う。CSR操作のtraceにはPC・元バイト・読出し／書込み有無・CSR前後の式・要求値を記録する。

初期PMPは既定で記号値。`--pmp-json examples/elf/pmp_zero_16.json`のように渡すと`cfg`と`addr`をそれぞれ16要素の配列で具体指定でき、入力ファイルのhashを出力する。`--reg xN=VALUE`を繰り返して初期GPRを指定できる。未指定のGPRは記号値、x0は0。探索上限は`--steps`と`--max-states`で指定する。

モデルは単一hart、M-mode、base PMP、4-byte grain、54-bit `pmpaddr`という仮定であり、Sailからの移植ではない。Sail 0.16と具体的な1命令列のみを照合した。メモリは初期値が任意のbyte arrayで、通常RAM・identity mapping・MPRV=0を仮定し、ELFのデータ初期値は与えない。`--mem8`/`--mem32`/`--mem64 ADDRESS=VALUE`で初期メモリの一部を具体化できる。load/storeはPMPとアラインメントを検査し、faultの可能性や実行領域へのstoreは`unknown`として残す。実装済みWARL部分集合外の設定書込み、未実装命令、間接呼出し、関数外への遷移、solverのunknownも`unknown`、ステップ上限は`bound_reached`。returnは関数ハーネスの終端で、callerへの復帰を実行したことにはならない。`--assume-mtvec-writable`はmtvecのdirect/vectored値が正確に読書きできるprofileを明示する。trap、割込みとHost、MMIO、PMA、キャッシュの効果は未接続で、SFENCEはイベントとして記録するだけである。現在の結果は攻撃や安全性の判定ではない。

`python3 -m smpreempt.exploration.explore_elf` が入口。
二つの機能を分けている。

- `extract`: 最終ELFからロード領域、シンボル、PCごとの機械語、モデル命令、直接の後続PC候補を取り出す。Z3不要。
- `reads`: ELF由来の命令を既存BMCに接続し、秘密レジスタだけ異なる二実行について、中断後のHostのバイト読取観測が異なる反例を探索する。Z3が必要。

現状はKeystone向けフロントエンドの基盤であり、Keystone全体の検証ではない。
generic研究用ELFの`pmp_unset`の抽出と限定実行は[実行記録](KEYSTONE_ELF_REAL_RUN.md)を参照。`reads`側は小さな手書き機械語ELFで入力から記号実行、反例の具体再実行までを確認した。

## Keystoneで最初に行うこと

対象のコミット、サブモジュール、プラットフォーム、コンパイラ、オプションを固定してビルドする。
シンボルを残した、最終リンク済みのSMコードを含むELFを使用する。裸のbin、未リンクの.o、ET_DYNは扱わない。
最終成果物がOpenSBI等と結合される構成なら、その実際のELFを指定する。

```sh
python3 -m smpreempt.exploration.explore_elf /path/to/sm-containing.elf \
  --entry destroy_enclave > results/keystone-extract.json
```

`instructions` の全レコードを保持する。未対応命令には `instruction: null` と理由を出す。
`transitions` は直接ジャンプ・分岐・逐次実行の後続候補。JALRは式で表す。
これは静的な後続候補であり、到達可能性判定済みのCFGではない。
呼出し先を含めて全実行セクションを取り込むため、関数境界で自動的に解析を打ち切らない。

PMPアクセス数、未対応命令の種類・到達PCを調べ、対象経路で必要な命令から意味論を追加する。
未対応命令を削除して次へ進むことや、関数を無条件に原子的な操作へ置換することはしない。

## 実行可能な小例

```sh
python3 examples/elf/build_fixture.py /tmp/erase.elf
python3 -m smpreempt.exploration.explore_elf /tmp/erase.elf

# a0 は公開ポインタ、a1 は秘密の入力値。秘密格納直後の漏えいを探索。
python3 -m smpreempt.exploration.explore_elf /tmp/erase.elf --analysis reads \
  --secret-reg 11 --reg 10=0x8000 --bound 3 \
  --host-pmp examples/elf/host_allow_all.json

# 全消去後の地点に観測を限定。
python3 -m smpreempt.exploration.explore_elf /tmp/erase.elf --analysis reads \
  --secret-reg 11 --reg 10=0x8000 --bound 3 --cut scrubbed \
  --host-pmp examples/elf/host_allow_all.json

# データの8バイトを隔離し、Host入口は実行可能にする候補PM。
python3 -m smpreempt.exploration.explore_elf /tmp/erase.elf --analysis reads \
  --secret-reg 11 --reg 10=0x8000 --bound 3 \
  --host-pmp examples/elf/host_isolate_word.json
```

小例は `sd a1,0(a0); sd zero,0(a0); jal zero,0`。
最初は深さ1、PC 0x1004で `counterexample`。後二つは `no_counterexample_within_bound` となる。
隔離のJSONは候補PMの入力であり、正解の保護集合を安全性条件として与えたものではない。
`host_deny_all.json` ではHost入口も実行できないため `incomplete: no feasible Host cut` になる。

## 読取検査の状態と仕様

各実行は既存 `SystemState` を使う。状態変数の名前空間を分け、BMCの式を一つのソルバに接続する。
共有するのは公開初期メモリと公開初期GPR。`--reg` 未指定の公開GPRも共有する任意値であり、暗黙のゼロではない。
`--secret-reg` のGPRだけ左右で独立した任意値になる（既定はx11）。x0は0。
ロードセグメントのファイル内容とBSSのゼロ初期化は左右で同一。その他のメモリは共有する任意配列。
PT_LOADの実体がないアドレスへのアクセス可否は、現在の小モデルのPMP/Bareの意味論に従う。
実機のRAM/MMIO配置の再現はまだ行わない。

各深さでSMの通常命令だけを実行し、二つの中断状態を比較する。深さはリタイアしたモデル命令数。
秘密によって分岐先が異なっても、同じ深さの二実行を比較する。`--cut` があれば両方のPCが指定集合にある場合だけ比較する。
PCや終了時刻そのものの観測、異なる深さ同士の比較は含めない。

各中断状態にPMのswitchoutを適用し、次を問い合わせる。

1. 両方でPMP設置・復元が可能で、Host入口0x1000にX権限がある。
2. 任意のアドレスaについて、読取成功可否が異なるか、両方読取可能かつ値が異なる。

安全性式にAやRは使わない。秘密のストア先をコードから導出する。
秘密の入力、公開値、公開観測の定義は必要であり、コードから自動推定していない。

`--initial-pmp` はSM開始時のPMP、`--host-pmp` はPMの候補テンプレート。
JSONは `cfg` と `addr` の8要素配列。文字列なら0x表記可。
既定の初期PMPは全OFF、SMはM-mode、Bare。Hostテンプレート省略時は中断時のPMPを維持する。
PMP設置の成否が秘密で変化する場合の観測はこの検査の対象外（両方で設置可能という条件付き）。

## 出力と再実行

- `counterexample`: 指定した部分モデルでHost読取観測に相違がある。PC・機械語・秘密入力・読取アドレスを出す。
- `no_counterexample_within_bound`: 検査した深さの観測について反例なし。無上限保証でも、関数全体の証明でもない。
- `incomplete`: 到達可能な未対応命令、コード外PC、fault、自己書換え候補、または実行可能なHost切替地点がない。
- `unknown`: Z3の時間切れ等。安全とは判定しない。

反例は、モデルが選んだ初期GPRと、LD・SD・Host読取に必要な初期バイトを具体化し、既存の具体Machineで再実行する。
各ステップのPC/GPR/PMPと触れるバイトを照合し、PM後のHost読取結果が実際に異なることも確認する。
`concrete_replayed: true` は既存Python具体モデルとの一致であり、QEMU/Spike/実機との一致ではない。
両モデルが共通に持つISA誤りはこの照合だけでは検出できない。

ELFのSHA-256、入口、公開・秘密入力の区別、深さ、選択地点、初期PMP・Host PMPを記録する。
コミットとビルド環境の記録は利用側で追加する。DWARFによる行番号対応は未実装で、シンボルとPCが対応の起点になる。

## 命令・ハードウェア範囲

ELF64 little-endian、RISC-V ET_EXEC、通常セクション・シンボル表を扱う。実行アダプタはPT_LOADの仮想・物理アドレス一致が必要。
拡張番号、セクションのないELF、重複セグメント、1MiB超のファイル由来ロードデータは未対応。

デコード対象はADD/ADDI/XOR/AND/LD/SD/BEQ/JAL/JALR、限定CSRW、全体SFENCE.VMA。
LUIは符号拡張した定数のADDI、AUIPCはそのPCを加えた定数のADDIへ正確に正規化する。
その他の演算・CSR、圧縮命令、原子命令、トラップ処理等は未対応。未知命令はlistingに残し、到達すればモデルギャップにする。
PMPは現在の8エントリモデルに従い、Keystoneが使い得る16エントリ全体はまだ表現しない。

最初の範囲は単一hart、抽象的な原子PM切替、命令フェッチは固定コードという前提。
実行領域に対するSDが到達可能なら未完了とする。命令フェッチ権限やRAM/MMIO境界の検証は含まない。
権限キャッシュ・多hart・IPI、実際の割込み到達可能性、割込みハンドラやPM命令列の途中状態は未接続。
「任意境界で中断」は追加機構を検討するための介入であり、現在のKeystoneがその境界で割込み可能であるという主張ではない。

## Keystoneの破棄処理へ進むための残り

1. 実際のELFで抽出を実施し、必要命令（圧縮・分岐・原子・CSR等）を追加。命令意味論を別実装で検証。
2. 関数開始時のメタデータ・スタック・PMP・秘密メモリ入力を与えるハーネスを追加。
   現状は秘密GPR入力だけなので、既存の秘密を消すdestroy_enclaveの入口仕様はまだ記述できない。
3. 消去ループを扱い、秘密データの格納から破棄まで、または証明済み入口契約から接続。
4. 16エントリPMP、キャッシュと同期、実機のhart構成・メモリ配置を接続。
5. Host書換え→再開→信頼された使用の完全性検査、baselineとの比較を追加。
6. 具体反例をQEMU/Spikeで再現し、必要なら帰納的不変条件・ループ要約で境界を超えた保証へ進む。
