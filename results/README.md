# 探索結果

生成JSONを置くディレクトリです。JSONはGitの追跡対象から除外しています。
リポジトリのルートから実行します。

```sh
.venv/bin/python -m smpreempt.exploration.explore_system --analysis attacks > results/attacks.json
.venv/bin/python -m smpreempt.exploration.explore_system --analysis pmp-sync > results/pmp-sync.json
.venv/bin/python -m smpreempt.exploration.explore_system --analysis states > results/states.json
.venv/bin/python -m smpreempt.exploration.explore_system --analysis program --bound 5 > results/system.json
```

`search-results.json` は旧列挙探索の保存結果です。比較用に残していますが、
現在の統合BMCの出力形式とは異なります。
# 意味に基づくメモリ安全性の実験

`python3 -m experiments.semantic_requirements > results/semantic_requirements.json`

秘密依存の読取、初期化、検証後の再読込みを、既存の命令意味論で調べる経路限定実験です。
`expected_results_match: true` は記載した各問合せの期待結果との一致を示します。
統合BMCの全経路検証を意味しません。仕様・範囲は [再検討](../docs/models/SEMANTIC_MEMORY_MODEL.md) を参照してください。
# LLVM IRの遷移抽出

`python3 -m smpreempt.exploration.extract_llvm examples/llvm/erase.ll --function erase > results/llvm-erase.json`

`effects.ll` に替えると関数呼出し・アセンブリ等の未定義効果も確認できます。
出力は構造的な遷移グラフであり、安全性判定や実行経路の列挙ではありません。
仕様は [LLVM_TRANSITIONS.md](../docs/llvm/LLVM_TRANSITIONS.md) を参照してください。

実際のvector-keystone generic構成での生成物は `keystone-generic-ir/` に保存します。
`capture.json` はIR生成条件、`link.json` はリンク入力、`destroy-linked-expanded.json` は呼出し展開後のグラフ、
`sbi-memset-summary.json` は途中prefixを残すループ要約と帰納検査、`analysis.json` は結果の概要です。
再現コマンドと保証範囲は [LLVM_ANALYSIS.md](../docs/llvm/LLVM_ANALYSIS.md) を参照してください。

# Keystone ELFとPMP命令

`keystone-generic-elf-patched/`に、generic研究用ELF、build manifest、`pmp_unset`の命令一覧・objdump照合・限定記号実行、Sailとの小ELF比較を保存しています。ファイル構成と仮定は [KEYSTONE_ELF_REAL_RUN.md](../docs/current/KEYSTONE_ELF_REAL_RUN.md) を参照してください。
