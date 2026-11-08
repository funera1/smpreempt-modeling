# 実機命令境界からのプリエンプション禁止区間導出

## 目標

対象のKeystoneを含む最終リンク済みRISC-V ELFを起点に、各機械命令の前の状態と、そこからHostへ切り替えた場合の安全性を解析する。結果は命令アドレスとCFGに対応付けて出力する。LLVM IR/DWARFは、EPMの範囲や管理データ等の意味を後から対応付ける補助情報として使う。

機構の前提は入力として固定する。少なくともCPU状態の保存・復元、Hostへの移行、PMPの変更可否を記述し、EPMのコピー・消去・移動は機構の動作に含めない。

## 処理のつながり

1. ELFとビルド情報からPC、命令長、opcode、operand、CFG候補を得る。未解決の間接分岐や未知命令は明示する。
2. GPR、CSR、メモリ、特権、PCを記号的に更新する。PMPはhartごとに保持し、当初の実行対象profileを固定する。
3. 到達条件と、メモリ管理・同期・Hostへの切替に必要な抽象状態を結び付ける。実装から推定できない意味は入力契約として明示する。
4. 各命令の前でPMを適用し、Hostから保護対象にアクセスできるかを検査する。同期やPMの意味が不足する経路はunknownとする。
5. 各PCの安全性、到達性、解析の完了状況と根拠を出力し、CFG上の禁止地点を構成する。状態依存の結果をPCだけで使う場合は、到達し得る全状態を保守的に集約する。

初回はPMP更新の観察に限定し、領域・初期PMP・関数引数を明示する。後続でEPMの消去・所有権、Host書換え後の信頼された使用を追加する。

## 判定の意味

- **safe**: 指定した初期状態集合とPMに対して到達状態の健全な過大近似が得られ、違反条件がunsat。
- **unsafe**: 到達可能な状態と違反を示す反例が得られ、必要な具体化・再検査を通った。
- **abstract counterexample**: 抽象モデルでは違反するが、具体的な実行可能性は未確認。
- **unknown**: 未対応命令・未知の間接分岐・探索の打切り・同期/PMの意味不足・solver unknown等。
- **unreachable**: 指定の入口・初期条件から到達不能と証明できた地点。未訪問だけでは到達不能としない。

有界探索のunsatは、その上限内で反例がないという結果である。全到達状態に対するsafeには固定点、帰納的不変条件など別途の完備性根拠が必要。安全性の空虚な成立を避けるため、入口条件と到達性も併せて報告する。

PC順に隣接する命令だけで区間を決めると、分岐・ループ・非連続配置を失う。まずCFGノードとして禁止地点を出し、実装上の制御箇所への集約条件と延期可能性を別に示す。

## 既存実装との差

- `smpreempt/frontend/elf.py`は独自の限定RV64 decoder。命令一覧と有界実行はLLVM MCのC APIも利用するが、MCInstの全operandの構造化は未対応。未対応命令は保持する。
- `smpreempt/model/symbolic_pmp.py`は8/16-entry base-PMPの部分モデル。`step_elf_pmp`はgeneric研究用Keystone ELFの一条件でCSR更新を追跡した。Sail 0.16とは小ELFの具体的な1命令列を照合したが、必要な命令・profileやWARLの網羅は未完了。
- `smpreempt/analysis/elf_analysis.py`には小さな入力に対する有界解析があるが、実Keystone ELFの全命令境界に対する到達可能状態・禁止区間を導出しない。
- `smpreempt/analysis/elf_preemption.py`はPMP維持・Host Bare・1 byte R/Wに限定した各命令境界の有界検査を実装。詳細は[命令境界の検査](ELF_PREEMPTION_BOUNDARIES.md)。実PM、同期view、無上限保証、禁止区間は未実装。
- LLVM IRのCFG・データフロー・inline asm抽出がある。IR上の`call asm`境界とELFの機械命令境界は同一視しない。
- Keystone/OpenSBIのgeneric研究用最終ELFをビルドし、`pmp_unset`を抽出・限定実行した。配備対象のELFや実機環境との一致は未確認。詳細は[実行記録](KEYSTONE_ELF_REAL_RUN.md)。

## 次の作業

1. generic研究用ELFとbuild provenanceを取得済み。実機向けビルドの条件との対応を確認する。
2. `pmp_unset`のPC・命令bytesを独立したobjdumpと照合済み。他の対象関数とMCInstの全operandの構造化に広げる。
3. 16-entry PMPの部分モデルでCSR前後の式を出力し、Sailとの具体的な1命令列の照合を実施済み。profileと入力の範囲を広げる。
4. PMPを維持する理想化したPMについて、Host直接アクセスを有界検査済み。実際のPM切替・同期と到達性の保証を追加する。
5. Keystoneの対象関数へ適用し、入口契約、未対応経路、保護対象と出力地点の対応を記録する。
6. LLVM/DWARFでEPM・消去対象への対応を追加し、機密性と完全性に別々の契約を与える。

命令デコードの正しさ、CSR/PMP意味論の正しさ、対象コードの到達性、Host移行の安全性は別々の検証課題として扱う。
