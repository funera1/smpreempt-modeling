# TODO

## 主目的：ELFの機械命令境界からプリエンプション禁止地点を導出

設計と現在の実装との差は [PREEMPTION_REGION_PLAN.md](docs/current/PREEMPTION_REGION_PLAN.md)。LLVM IRはEPM・管理データ等の意味情報として後から接続する。

- [x] Keystone/OpenSBI genericの研究用最終ELFとビルド条件を取得。配備対象との一致は未確認。
- [ ] 実Keystone ELFにLLVM MCを適用し、対象関数の命令・operand・PC・CFG候補を独立のデコード結果と照合。
  `pmp_unset`のPC・命令バイトはobjdumpと487/487一致。全opcode/operandの意味と他関数の照合は未完了。
  LLVM MC C APIによる関数範囲の命令表示、PMP CSR・SFENCEのbit field分類とCFG候補は合成ELFで実装・確認済み。MCInst全operandの構造化は未対応。
- [ ] 対象経路の記号命令意味論と16-entry PMP profileを整備し、版を固定したSailと比較。
  実ELFの`pmp_unset`について一条件下でCSR更新まで追跡。Sail 0.16とは同じ機械語を含む小ELFのPMP CSR 5イベントが一致。圧縮命令の残り・関数間実行・多様なWARL/lockのSail照合は未対応。
- [ ] 明示したPMと初期条件のもとで各命令境界をsafe / unsafe / abstract counterexample / unknownに分類し、到達性と探索完備性を報告。
  PMP維持・Host Bare・1 byte R/W・現在PMP viewの仮定に限り、実ELFの有界検査を接続。保護領域は手動入力で、PM実装、Host入口、同期cache、無上限のsafe、具体反例再実行は未対応。詳細は[ELF_PREEMPTION_BOUNDARIES.md](docs/current/ELF_PREEMPTION_BOUNDARIES.md)。
- [ ] EPMの消去・所有権および再開後の完全性を接続し、CFG上の禁止地点から実装可能な制御区間を導出。

## 実装からのモデル抽出と正確性確認

実行・分析の結果は [KEYSTONE_EXTRACTION_RESULTS.md](docs/llvm/KEYSTONE_EXTRACTION_RESULTS.md)。

- [x] LLVM命令辺に対する小さな記号実行器を接続し、整数・分岐・GEP・load/store・PHI・returnを有界実行。
- [ ] LLVM objectの範囲・alias・poisonメモリを状態に追加。
- [x] 対応inline asm内のCSR/PMP操作を命令順に状態更新し、`SFENCE.VMA`を個別イベントとして記録。
- [x] `llvm.memset`と直接定義関数呼出しを、記号メモリ更新・呼出しフレームへ接続。
- [ ] 未対応intrinsic/asm/外部呼出しを、対象実装の意味に基づく遷移または明示契約へ接続。
- [ ] 実装由来ループの帰納要約とbounded実行を統合し、長い消去列を扱う。
- [ ] 抽出したPMP設定・同期状態を、Hostの実効アクセス判定へ接続。

Keystoneの`pmp_init`は87辺でreturnし、8エントリ分のPMP CSR更新と`SFENCE.VMA`の列を確認済み。実行器の範囲・使い方は [LLVM_BOUNDED_EXECUTION.md](docs/llvm/LLVM_BOUNDED_EXECUTION.md)。これは限定subsetの実行確認である。

実行器の使い方と適用範囲は [LLVM_BOUNDED_EXECUTION.md](docs/llvm/LLVM_BOUNDED_EXECUTION.md)。

- [x] Keystone取得済みIRの9関数を抽出し、45項目の構造・由来チェックを確認。
- [x] generic platform archiveの全119個のCファイルをIR化・リンクし、ipi.cとOpenSBIの本体を取得。
- [x] 関数CFG共有による深さ制限のない直接呼出しと、根拠付きcallback候補を接続。
- [x] IPIの登録・要求内callback保存と、条件付きenqueue/dequeue移送関係を抽出。
- [ ] callback対象のalias／完全性、FIFO移送とイベントID対応の契約を検証。

接続結果と条件は [SHARED_CFG_IPI.md](docs/llvm/SHARED_CFG_IPI.md) を参照。
- [ ] 実IRに現れたasmの `rK` 制約と未取得のthread/platform関数を扱う。

- [x] 抽出・状態モデル・Keystone接続・探索／検証のディレクトリを分離し、importを更新。
- [x] LLVM命令とRISC-V操作語彙・状態変数の対応を、CFG付きの統一した抽出結果へ接続（対応済み部分集合、未知は障壁）。
- [x] 各遷移の命令・関数・ソース位置と、抽出事実／抽象化の仮定を明示。
- [x] 関数内／関数間CFGと抽出結果の対応をテストで確認。
- [ ] 他hartへの委譲・間接呼出し・未知のasmと制約形式を、実装に即した契約／抽出で接続。
- [ ] 最終ELFとの対応でasmの擬似命令・alignmentの機械命令境界を確定。

以下は研究全体の残作業。LLVM側の抽出結果、ELF境界検査、従来の攻撃探索は、それぞれの前提と実行結果を区別する。

## 意味に基づくメモリ安全性

### RISC-V操作の共通表現（実装非依存の起点）

- [x] 内容・PMP・変換/PTE・同期・特権・属性等の22操作群を宣言的な遷移として列挙。
- [x] CSRの6形式とalias、Store/AMO/SC、フェンス等をデコード済み入力から正規化。
- [x] CSR一命令のatomicな境界、読書き抑止、PTEの文脈付き分類、局所フェンス範囲を保持。
- [ ] LLVM/ELF/アセンブリからこの語彙へ結びつける（現在は明示JSON入力）。
- [ ] 基本PMP・同期のprofileを選び、宣言中の意味関数を実際の状態遷移へ接続。
- [ ] 必要なSmepmp・ページ変換・拡張・platformの意味と例外を追加。

一覧・保証範囲は [RISCV_MEMORY_OPERATIONS.md](docs/models/RISCV_MEMORY_OPERATIONS.md)。

### LLVM IRからの遷移抽出（補助解析）

- [x] LLVM公式パーサ・検証器で .ll/.bc を読み、命令単位の条件と効果を抽出。
- [x] 分岐・switch・PHI同時更新、ループの循環構造を展開せず保持。
- [x] 型付きload/store、alloca、GEPのレイアウト情報を抽出。アクセス権は評価しない。
- [x] 呼出し・memset・アセンブリ・atomic/volatile等を未定義効果として明示。
- [x] 小さなIRで抽出と検証を実施（LLVM 18/20、bitcodeも確認）。
- [x] 指定された vector-keystone の enclave.c と OpenSBI sbi_string.c をgeneric RV64構成で実際にIR化し、由来を記録。
  コミット01d9e192… / OpenSBI v1.1。対象ボードの配備ビルドとの同一性は未確認。
- [x] 定義のある直接呼出しを展開。再帰・深さ制限・外部効果は障壁として保持。
- [x] 直線区間のメモリ更新を合成し、ロードの参照時点と途中状態を保持。
- [x] 厳密に一致する消去/byte-fillループをprefix kで要約し、SMTで条件付き帰納性を検査。
- [x] 整数幅・主要poisonフラグ・UB、明示的なメモリobjectによる限定的な実行意味論を接続。
- [x] 実際の destroy_enclave の8箇所のsbi_memsetを本体へ展開し、sbi_memsetのループ要約を検査。
- [ ] 対象ボードを確定した配備ビルドのコンパイル条件と照合する。
- [ ] 残る外部呼出し、原子操作、volatile、アセンブリ等の意味・契約を必要な範囲で追加。
- [ ] 要約の前提（live object・サイズ・no-wrap等）が呼出し元で成立することを検査。
- [ ] 任意CFG/呼出しフレーム全体の実行、global初期化、pointer load/store、metadata/属性の完全な意味論を拡張。
- [ ] 安全性仕様・アクセス制御・ELFとの対応は抽出後の別解析として接続。

使い方と範囲は [LLVM_TRANSITIONS.md](docs/llvm/LLVM_TRANSITIONS.md)、
今回の接続と実験結果は [LLVM_ANALYSIS.md](docs/llvm/LLVM_ANALYSIS.md)。

### 実装ELFとの接続

- [x] ELF64/RV64のロード領域・シンボル・命令・後続PC候補を抽出。未対応命令を保持。
- [x] ELF命令を二実行BMCとPM後のHost読取比較へ接続し、具体モデルで反例を再実行。
- [x] 小ELFで消去前の漏えい・消去後の読取・候補PM隔離・モデルギャップを検査。
- [ ] generic研究用Keystone ELFの他の対象関数・経路に抽出を広げ、到達する未対応命令を追加。配備ビルドとの違いも確認。
- [ ] 破棄処理入口の秘密メモリ・管理構造・スタック・PMPを与えるハーネスを追加。
- [ ] 実装に合わせた16エントリPMP・原子命令・圧縮命令・キャッシュ・多hart同期を接続。
- [ ] DWARFソース対応とQEMU/Spikeでの反例再現を追加。
- [ ] ELF経路のHost書換え・再開後使用とbaseline比較を追加。

詳細・実行例・現在の制限は [KEYSTONE_ELF.md](docs/current/KEYSTONE_ELF.md)。

### 安全性仕様と統合

詳細は [再検討](docs/models/SEMANTIC_MEMORY_MODEL.md)。以下の履歴中心の項目は既存モデルの課題であり、新方式の前提ではない。

- [x] 現行コードの表現力と不足、機密性・完全性・PMP実現可能性を整理。
- [x] A/Rを安全性判定に使わず、消去・初期化・TOCTOUの経路限定記号実験を実装。
- [ ] 秘密入力・公開観測・信頼使用・拒否・正当な公開の最小契約を定義。
- [ ] 統合BMCの遷移と安全性式を分離し、記号初期入力と二実行用の変数名前空間を追加。
- [ ] prefix→Host操作→suffixと基準実行を接続し、全分岐と未完了経路を分類。
- [ ] 複数Host書換えのフレーム関係を接続し、単一書換え実験との範囲差を明示。
- [ ] 意味上の読取・書込要求とPMP/キャッシュ/同期を結合し、候補PMを検査。
- [ ] PMの観測に基づく方策、Hostの必要権限、再開後の機能性を仕様化。
- [ ] baseline脆弱性と追加攻撃を分離し、地点延期・PMP資源を評価。
- [ ] 統合BMCの反例再検査を修正：fresh PMPのみの検査ではキャッシュだけで成立する反例を再現できない。

## 既存モデル: Hostだけで完結する攻撃

- [x] 任意中断状態→Wout→Hostの直接データ読取/書換えをGなしでモデル化。
- [x] PMP設置不能・入口権限不足・復元不能を、データ攻撃と分けて報告。
- [x] 読取と実際の値の改変を別々に探索し、LBU/SBとして射影を再実行。
- [x] 固定PMP/RのHostデータ操作について、任意回の変更のフレーム関係を定義。
- [ ] この範囲で攻撃成立状態を整理し、必要な状態条件の説明を蓄積する。
- [ ] HostのCSR/アドレス変換や実行権限等、未モデル化のHost単独の観測経路を整理。
- [x] 合法な過去アクセスの来歴を持つ代表PMP権限キャッシュと、SFENCEによる無効化を追加。
- [x] PMP更新後の同期あり/なしを比較し、現在PMPが拒否する場合の古い許可による攻撃を探索。
- [x] 全体SFENCEとCSRW satpを記号BMCに接続。satp書込みでキャッシュを自動消去しない。
- [ ] 複数エントリ・ASID・変換モード・過去PMPロックを含むキャッシュ来歴を拡張/検証。
- [ ] 直接攻撃の分類後に、resume/invokeを介した攻撃を別モデルとして追加。

詳細は [Host単独攻撃](docs/history/HOST_ONLY_ATTACKS.md)。
Gの十分性検証は補助機能として残し、攻撃探索に先立つ除外条件にはしない。

## 研究仕様（最優先）

目標は共通PMの切替操作と中断可能条件の導出、その後のSM構造変更による延期区間の短縮。
詳細は [研究方針](docs/history/RESEARCH_DIRECTION.md) を参照。

- [x] まず表現可能状態K0でPM/中断条件を設計し、高コストなら到達可能性で絞る方針を採用。
- [x] Bare部分モデルのK0を定義し、到達可能性によらずPC/GPR/M/A/PMPを記号化する。
- [x] K0からの切替をSM命令列なしで検証し、許可/拒否状態の存在も検査する。
- [ ] K0をCSR/V/特権まで拡張し、アーキテクチャの全形式制約と信頼前提を精密化する。
- [ ] 保存量・保護資源・判定/切替時間・中断制限を評価する。
- [ ] 任意SMに課す最小契約と、プリエンプションなしの基準モデルを定義する。
- [ ] PMの観測O・操作能力と、Hostの合法操作・要求範囲を定義する。
- [x] 切替操作Wout/Winと、中断許可条件Gを独立に表現する。
- [ ] 観測不足や機構の能力限界を証明し、より弱いGや別のWを検討する（現在は候補検証）。
- [ ] 固定SMのBMCと、適合する全SMに対する共通保証を区別する。
- [ ] 直接隔離、再開後の機密性/完全性、最大中断延期時間を別々に定義する。

## 現在の実装からの拡張

- [x] 新制御経路で中断要求をpendingにし、SM継続後の安全地点で処理する。
- [ ] SMが有限時間で許可状態に達する条件を定義・検証する。
- [ ] 記号的な初期入力と、CSR/V/特権の動的遷移を追加する。
- [ ] Hostモデルが合法S-mode操作の何を包含/省略するか根拠を示す。
- [ ] invokeと再入の許可/拒否を定義する。
- [ ] fault後のトラップ/PM dispatch、C↔SMの正規遷移を扱う。
- [ ] 通常メモリのHost変更と再開後の整合性を検査する。
- [ ] Sv39、TLB/フェンス、命令フェッチとISA/Sailとの対応を検証する。
  全体SFENCEと代表キャッシュは実装済み。選択的フェンスとSv39ウォークは未対応。

## 履歴と領域管理

- [ ] 履歴の開始単位と解除条件を決める。現在は作成時から単調累積。
- [ ] 履歴に命令フェッチ・ページウォークを含めるか決める。
- [ ] 未アクセス領域とSM/PM自身の保護に必要なR_fixedを定義する。
- [ ] 共有メモリの過剰保護と、Host実行を両立する条件を整理する。
- [ ] 履歴からのPMP合成を検討する。粒度・エントリ数・ロックも扱う。

## 証明と構造変更

- [ ] 必要な場合だけ対象をK1へ絞り、Reachable ⊆ K1 ⊆ K0の根拠と追加コストを示す。
- [ ] 初期成立・保存性・目標含意を個別に検証する帰納的不変条件を作る。
- [ ] 抽象PMを実現可能な命令列へ落とし、CSR書込順序等を検証する。
- [ ] 第1段階の限界から、マイクロカーネル化等の比較指標を定める。

## 実装済みの基盤

- [x] 具体命令モデル・PMP・原子的PM・アクセス履歴。
- [x] 基本9命令とPMP更新の記号遷移。
- [x] 命令選択・Host操作・繰返し中断/再開を接続したBMC。
- [x] 反例の具体再実行と状態照合、未対応経路の識別。
- [x] 無条件Gと隔離Gの比較、K0に対する切替検査、全状態拒否の識別。
- [x] 旧列挙/BFS/Host窓探索を削除し、実行入口を統合BMCへ集約。

現在の範囲は [統合BMC](docs/history/COMPOSED_BMC.md)、
命令定義は [命令遷移](docs/models/INSTRUCTION_TRANSITIONS.md) を参照。
