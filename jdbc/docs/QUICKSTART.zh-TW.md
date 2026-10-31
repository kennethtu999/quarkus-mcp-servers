# 安裝與交付

完整中文用法、整段設定 sample、讀寫 MCP 的 JSON／TOML 接入方式，統一見安裝包根目錄的 [README.md](../README.md)。

## 使用者

1. 安裝 Java 17+、Python 3，解壓完整 ZIP 到固定目錄。
2. 在 `dbmcp` 目錄執行 `sh onboarding.sh`。
3. 先看既有 DB 狀態，再依 sample 貼上整段連線／權限設定，最後一行 `END`。
4. DB／MCP 驗證通過後，可選註冊預設 client；不同專案使用不同 DB 時，依根目錄 README 的專案設定範例接入。

onboarding 顯示兩組 sample 並設定／驗證 DB；驗證後可選註冊到預設 Codex／Claude／Pi／OpenCode。選 `0` 則不修改 client 設定；不處理 `~/bin/*.sh` 自訂啟動腳本。
每人各自 init；不要將連線密文與 master key 發給其他人。

## 維護者建置

在 repository 根目錄：

```sh
./mvnw -pl jdbc -am verify -Pbundle-db2
python3 -m unittest discover -s jdbc/scripts -p 'test_*.py'
python3 jdbc/scripts/smoke_stdio.py java -jar jdbc/target/mcp-server-jdbc-999-SNAPSHOT.jar
python3 jdbc/scripts/package.py --bundled-db2
```

交付 `jdbc/target/dbmcp-local-db2.zip`、同名 `.zip.sha256` 與來源 commit。此 bundled 版本含 Db2 JCC 12.1.5.0、PostgreSQL、Oracle driver；發送前確認組織的 driver 再散布權限。
一般不含 Db2 的版本省略 `-Pbundle-db2` 與 `--bundled-db2`，使用者自行安裝並 pin JCC driver。

升級前以 `ai-db-mcp backup create <備份目錄>` 備份，master key 另行保管；關閉 client，替換程式安裝目錄，保留使用者設定目錄，再重跑 onboarding 的狀態／連線驗證。
真實 Db2、PostgreSQL、Oracle 的待驗證項目見 [RISKS.md](RISKS.md)，信任邊界見 [SECURITY.md](SECURITY.md)。

## Linux 驗證

已用 macOS `container` 驗證 Ubuntu 22.04 與 Red Hat UBI 9（Java 17、arm64）：無桌面／Secret Service 的首次初始化、自動 `~/.config/dbmcp/` key file 與 0700／0600 權限、重啟解密、多程序 MCP 握手、遺失 key 不重建與不可用 DBus。容器測試使用假連線與 `--skip-connection-test`，不代表已完成真實 DB 或完整 RHEL 桌面環境驗證。維護者可將 JAR 唯讀掛載到容器 `/bundle/ai-db-mcp.jar`，再於 host 執行 `python3 jdbc/scripts/smoke_linux_container.py <container-name>` 重現。
