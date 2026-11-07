# 探索結果

生成JSONを置くディレクトリです。JSONはGitの追跡対象から除外しています。
リポジトリのルートから実行します。

```sh
.venv/bin/python -m smpreempt.exploration.explore_system --analysis attacks > results/attacks.json
.venv/bin/python -m smpreempt.exploration.explore_system --analysis states > results/states.json
.venv/bin/python -m smpreempt.exploration.explore_system --analysis program --bound 5 > results/system.json
```

`search-results.json` は旧列挙探索の保存結果です。比較用に残していますが、
現在の統合BMCの出力形式とは異なります。
