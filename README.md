## 使用方法

Sigmaルールを取得
```
Invoke-WebRequest "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip" -OutFile "sigma.zip" Expand-Archive "sigma.zip" -DestinationPath "./sigma"
```

マッピングファイルを取得
```
Invoke-WebRequest "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/refs/heads/master/mappings/sigma-event-logs-all.yml" -OutFile "./mappings/sigma-event-logs-all.yml"
```

セキュリティログ取得
```
& C:\admin\evtx-retriever\evtx_retriever.ps1
```

chainsawの脅威検出を実行（コンテナの起動）
```
docker compose run --rm chainsaw
```
***

### ディレクトリ構成
このプログラムのディレクトリとファイル構造は下記の通り
```
/project-root
  ├── Dockerfile
  ├── docker-compose.yml
  ├── sigma/
  │     └─ sigma-master/
  ├── scripts/
  │     └─ scan_and_report.py
  ├── rules/
  ├── reports/
  ├── mappings/
  │     └─ sigma-event-logs-all.yml
  └── evtx/
        └─ hostname/
            └─ eventlog.evtx
```