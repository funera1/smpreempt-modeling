# Keystone generic ELFでのPMP命令抽出と限定実行

## 対象とビルド

Keystone `01d9e19206a2d15ba5485d32d193eea381634979`とOpenSBI `4489876e933d8ba0d8bc6c64bae71e295d45faac`を使ったgeneric RV64の研究用`fw_jump.elf`を作成した。Keystone同梱の`opensbi-firmware-secure-boot.patch`を、OpenSBIの一時コピーに適用している。元のKeystone/OpenSBI checkoutは変更していない。

ELFのSHA-256は`32381fa9cbdbec4cbcbee8092cf8a23c3ea79b492c6ea31cfa239660906f8ac3`。Clang 20.1.2、LLD 20.1.2、`rv64imafdc_zicsr_zifencei`、`lp64d`、`FW_PIC=n`、`FW_JUMP=y`でビルドした。配備バイナリとの一致は未確認。generic platformはentropy sourceを持たないテスト構成である。

成果物とビルド条件は`results/keystone-generic-elf-patched/`にある。`build-manifest.json`にコマンド、環境、各リポジトリのcommit、パッチ・ELF・ツールパッケージのhash、`build.log`にビルド結果を記録した。`results/`はgit管理外。

## 命令一覧と境界の照合

```sh
python3 -m smpreempt.exploration.inspect_elf_pmp \
  results/keystone-generic-elf-patched/platform/generic/firmware/fw_jump.elf \
  --function pmp_unset --build-metadata results/keystone-generic-elf-patched/build-manifest.json \
  > results/keystone-generic-elf-patched/pmp_unset.inventory.json
```

`pmp_unset`は`0x80017836`から1,592 bytesで、静的一覧は487命令（2-byte 178、4-byte 309）。GNU RISC-V objdump 2.42の出力とPC・命令バイトを比較し、487/487箇所が一致した。これは命令境界とバイトの照合であり、到達性や意味論の証明ではない。

```sh
python3 -m smpreempt.exploration.compare_objdump \
  results/keystone-generic-elf-patched/pmp_unset.inventory.json \
  results/keystone-generic-elf-patched/pmp_unset.objdump.txt
```

## 一つの初期状態での記号実行

PMP entry 0を`cfg=0x1f, addr=0x2000`とし、region ID 0、stack pointer、bitmap、領域indexとジャンプテーブルの1要素を指定した。ジャンプテーブルの値はELFの対応bytesから取得した。`mtvec`のdirect/vectored値が正確に書き戻せる仮定を明示的に有効化した。

```sh
python3 -m smpreempt.exploration.step_elf_pmp \
  results/keystone-generic-elf-patched/platform/generic/firmware/fw_jump.elf \
  --function pmp_unset --steps 150 --max-states 100 --timeout-ms 2000 \
  --pmp-json examples/elf/pmp_entry0_napot_16.json \
  --reg x2=0x90000000 --reg x10=0 \
  --mem32 0x80057a54=1 --mem32 0x80057a7c=0 \
  --mem64 0x80025110=0x80017870 --assume-mtvec-writable \
  > results/keystone-generic-elf-patched/pmp_unset.entry0.steps.json
```

探索した命令状態は50、初期メモリの未指定部分に依存して43命令・45命令の2経路が関数ハーネスのreturnへ到達した。共通部分の一部は以下。

| PC | 命令 | この入力での状態更新 |
|---|---|---|
| `0x80017872` | CSRRS `pmpcfg0` | `0x1f`を読取り |
| `0x80017882` | CSRRW `mtvec` | 退避して`0x80017894`へ設定、仮定付き |
| `0x80017886` | CSRRW `pmpaddr0` | `0x2000 → 0` |
| `0x8001788a` | CSRRW `pmpcfg0` | `0x1f → 0` |
| `0x8001788e` | `SFENCE.VMA` | イベントを記録 |
| `0x80017894` | CSRRW `mtvec` | 退避した値へ復元、仮定付き |

これは手動で与えた状態の限定実行で、ブートからその状態へ到達する証明ではない。初期メモリの大半は任意、通常RAM・MPRV=0・単一hart等を仮定している。Host移行、同期キャッシュ、例外・割込み、未知命令やすべての呼出しは未接続。

上記のメモリ値と`mtvec`の仮定を与えない別の実行では31命令状態を探索し、3経路とも`unknown`になった。2経路は`sbi_printf`への関数外呼出し、1経路は`0x8001786e`の記号的なジャンプ先で停止した。結果は`pmp_unset.unconstrained-memory.steps.json`に保存している。

## Sailとの限定比較

[Sail RISC-V公式リリース](https://github.com/riscv/sail-riscv/releases/tag/0.16)の0.16（git `e5acebb`）の実行モデルを利用。既定profileはRV64、PMP 16 entry、grain 0、物理アドレス幅56 bit。配布archiveのSHA-256は`f9bb8a32b8f3eddbdf69b3a29d96dff4ba1e77f45877165e0478418367da6bee`。

`examples/elf/pmp_sail_compare.S`から作った小ELFでentry 0を設定し、Keystone `pmp_unset`のCSR read、ANDI、アドレス書込み、設定書込み、SFENCEと同じ機械語を実行した。LLVM/Keystone ELFとの命令バイトは5箇所が一致。Sailと本モデルのPMP CSR読取り・書込み5イベントはPC、順序、値が一致した。traceと`compare_sail_pmp`の結果は同じ`results/`に保存。

この比較は具体的な1入力・1命令列についてのものであり、実Keystone ELF全体をSailで実行した結果でも、`mtvec`やSFENCEの効果、16エントリ全体の正しさ、全WARL/lock組合せの証明でもない。

同じツール配置での再実行例:

```sh
/tmp/smpreempt-clang/bin/clang --target=riscv64-unknown-elf \
  -march=rv64imac_zicsr_zifencei -mabi=lp64 -c \
  examples/elf/pmp_sail_compare.S -o /tmp/smpreempt-pmp-sail.o
/tmp/smpreempt-riscv-tools/usr/bin/ld.lld -m elf64lriscv -N \
  -Ttext=0x80000000 -e _start /tmp/smpreempt-pmp-sail.o -o /tmp/smpreempt-pmp-sail.elf
/tmp/sail-riscv-Linux-x86_64/bin/sail_riscv_sim --trace-instr --trace-csr \
  --stop-at-pc 0x80000028 --inst-limit 30 /tmp/smpreempt-pmp-sail.elf \
  > /tmp/smpreempt-sail-trace.txt 2>&1
python3 -m smpreempt.exploration.step_elf_pmp /tmp/smpreempt-pmp-sail.elf \
  --function _start --steps 20 --pmp-json examples/elf/pmp_zero_16.json \
  > /tmp/smpreempt-pmp-sail-model.json
python3 -m smpreempt.exploration.compare_sail_pmp \
  /tmp/smpreempt-pmp-sail-model.json /tmp/smpreempt-sail-trace.txt --sail-version '0.16 e5acebb'
```

比較器は両者に同じELF・初期profileを与えたことを自動判定しない。PMP CSRイベントのPC・read/write・値を照合し、イベント欠落や値の不一致を`mismatch`とする。
