# Keystone / OpenSBIの全CファイルをIR化する

従来の3ファイル限定入力に代わり、generic構成のplatform archiveを構成する
全Cコンパイルコマンドを実際のOpenSBI makeから取得し、一括IR化・リンクする。
入口は `smpreempt.exploration.capture_keystone_all`。

```sh
python3 -m smpreempt.exploration.capture_keystone_all \
  ~/repo/vector-keystone \
  --opensbi /tmp/smpreempt-opensbi-v1.1 \
  --clang /tmp/smpreempt-clang/bin/clang \
  --output-dir results/keystone-complete-ir
```

この環境では上記のClangとOpenSBI checkoutを準備済み。別環境では実在するパスに置き換える。
対応profileは現時点でgeneric RV64、OpenSBI v1.1。配備ボードとの同一性は主張しない。

## 処理内容

1. `libplatsbi.a` を対象に `make -n -B` を実行し、対象構成の全コンパイルコマンドを取得。
2. makeログからコンパイラ引数だけを構造化して記録。ログのshell断片を実行しない。
3. ビルド出力下の生成Cファイルを、本来のmakeルールで生成。
4. 各Cファイル固有のinclude・define・ABI・最適化設定を保ってLLVM IRへ変換。
5. 全Cファイルの成功を確認してリンク。失敗があれば部分集合を完成品としてリンクしない。
6. 定義済み関数・未解決直接呼出し・間接呼出しを集計。

出力名にはソースの絶対パスのハッシュを付け、異なるディレクトリの同名Cファイルが衝突しないようにする。
各ファイルのコマンド・ソースとIRのSHA256・コンパイラ出力をmanifestに残す。
元のKeystone/OpenSBI checkoutに変更は加えず、生成物はoutput-dirへ保存する。

## 出力

- `make-command.json` / `make-dry-run.log`：対象構成のmake呼出しとログ。
- `compile_commands.json`：Cとアセンブリを含む取得済みコマンド。
- `generation.json`：生成Cファイルのmake実行記録。
- `units/*.ll`：各CファイルのIR。
- `batch-capture.json`：各ファイルの成功／失敗、ハッシュ、アセンブリ除外一覧、profile。
- `linked.ll`：全Cファイルのリンク結果。
- `coverage.json`：関数定義と未解決callの所在。

`status: captured` は全Cファイルの取得成功を意味し、アセンブリや間接呼出しの意味が解決済みという意味ではない。
C以外のコンパイル単位は `skipped` に明示する。

## 2026-11-07の実行結果

- Cファイル119個すべてをIR化してリンク。
- アセンブリ6個は別途抽出が必要な入力として記録。
- 関数定義634個、リンク済みIRは約7.4MB。
- `send_and_sync_pmp_ipi`、`sbi_pmp_ipi_local_update`、`sbi_tlb_request`、
  `swap_prev_state`、`clean_state`、PMP補助関数の本体が入力に揃った。
- 定義のない直接callは875箇所。うち854箇所はLLVM intrinsic、残り21箇所はアセンブリ関数が中心。
- 間接callは126箇所。callback・platform関数ポインタの接続は別の抽出処理が必要。
- 実行後、Keystone/OpenSBIのgit作業ツリーはどちらも変更なし。

全体テストは133件すべて成功。ファイルごとのフラグ保持、同名ソースの衝突回避、
欠落ソースの報告、アセンブリの別記、リンク後の定義解決もテストした。

## 状態遷移抽出への入力

```sh
python3 -m smpreempt.exploration.extract_llvm \
  results/keystone-complete-ir/linked.ll \
  --abstract-model --function send_and_sync_pmp_ipi --call-depth 4 \
  > results/keystone-complete-ir/ipi-transitions.json
```

本体の欠落はこの入力取得で解決できるが、関数ポインタを通すcallbackの実行辺、
IPIのhart間実行、LLVM intrinsicやアセンブリの意味までは自動的に確定しない。
また、既存の呼出し展開器は箇所ごとに本体を複製するため、入力が増えるとグラフも大きくなる。
IR取得範囲と呼出し展開深さは別の設定として扱う。

今回のリンク結果で抽出も実行した。深さ4で `send_and_sync_pmp_ipi` 起点は614ノード／683辺、
`destroy_enclave` 起点は3,957ノード／4,393辺になった。
後者では8箇所の `send_and_sync_pmp_ipi` 呼出しが本体へ展開された。
さらに先の56箇所は呼出し展開の深さ制限で残る。定義不足と深さ制限は別の理由として記録される。
