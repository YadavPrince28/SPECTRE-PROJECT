# ==============================================================================
# SPECTRE AUTOMATED BATCH RUNNER & MEMORY WATCHDOG
# Optimized for Heavy Banking APKs & Low-Memory Environments
# ==============================================================================
$ErrorActionPreference = "Stop"

$TOTAL_SCOPE = 166
$BATCH_SIZE  = 1
$LOG_FILE    = "data\validation\benchmark_execution_log.csv"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SPECTRE BATCH ORCHESTRATOR (1-APK ISOLATION & CACHE FLUSH) " -ForegroundColor Cyan
Write-Host " Total Target Scope: $TOTAL_SCOPE APKs"                      -ForegroundColor Cyan
Write-Host " Batch Execution   : $BATCH_SIZE APK per process cycle"        -ForegroundColor Cyan
Write-Host " Execution Log     : $LOG_FILE"                              -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

while ($true) {
    # 1. Parse unique completed packages from the log CSV
    $completed = 0
    if (Test-Path $LOG_FILE) {
        try {
            $csvData = Import-Csv -Path $LOG_FILE
            $completed = ($csvData | Select-Object -ExpandProperty package_name -Unique | Measure-Object).Count
        } catch {
            $lines = (Get-Content $LOG_FILE | Measure-Object -Line).Lines
            if ($lines -gt 1) { 
                $completed = $lines - 1 
            }
        }
    }

    $remaining = $TOTAL_SCOPE - $completed
    Write-Host "`n>>> Progress: $completed / $TOTAL_SCOPE completed ($remaining remaining) <<<" -ForegroundColor Yellow

    if ($completed -ge $TOTAL_SCOPE) {
        Write-Host "`n[SUCCESS] All $TOTAL_SCOPE APKs successfully evaluated!" -ForegroundColor Green
        Write-Host "[SUCCESS] Complete feature matrix logged for XGBoost meta-classification." -ForegroundColor Green
        break
    }

    # 2. Execute next APK in an isolated Python process
    Write-Host "[BATCH] Launching sample $($completed + 1)..." -ForegroundColor White
    python scripts\benchmark_accuracy.py --resume --max-samples $BATCH_SIZE

    # 3. Purge MobSF decompiler cache and scratch directories inside Docker
    Write-Host "[MAINTENANCE] Purging MobSF container upload/download cache..." -ForegroundColor Gray
    try {
        docker exec mobsf sh -c "rm -rf /root/.MobSF/uploads/* /root/.MobSF/downloads/* /root/.MobSF/signatures/*" 2>$null
    } catch {
        Write-Host "[WARN] Could not purge MobSF internal files." -ForegroundColor Yellow
    }

    # 4. Restart MobSF container to release Java JADX heap memory back to WSL2
    Write-Host "[MAINTENANCE] Cycling MobSF container to free JADX heap..." -ForegroundColor Gray
    try {
        docker restart mobsf | Out-Null
        Start-Sleep -Seconds 3
    } catch {
        Write-Host "[WARN] Failed to restart MobSF container." -ForegroundColor Yellow
    }

    # 5. Force Linux kernel inside WSL2 to drop dirty page caches
    Write-Host "[MAINTENANCE] Flushing WSL2 page cache..." -ForegroundColor Gray
    try {
        wsl -u root sh -c "echo 3 > /proc/sys/vm/drop_caches"
    } catch {
        Write-Host "[WARN] Could not drop WSL caches." -ForegroundColor Yellow
    }

    # 6. Check host physical RAM headroom
    $freeRAM = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
    Write-Host "[RESOURCE] Host Available RAM: $freeRAM GB" -ForegroundColor Green

    # 7. Deep restart safeguard if RAM drops below 2.0 GB
    if ($freeRAM -lt 2.0) {
        Write-Host "[RESOURCE GUARD] RAM under 2.0 GB ($freeRAM GB). Recycling WSL2 subsystem..." -ForegroundColor Yellow
        wsl --shutdown
        Start-Sleep -Seconds 4
        
        Write-Host "[RESOURCE GUARD] Starting MobSF container..." -ForegroundColor Yellow
        docker start mobsf | Out-Null
        Start-Sleep -Seconds 3
        
        $postRAM = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
        Write-Host "[RESOURCE GUARD] Restored Host RAM: $postRAM GB" -ForegroundColor Green
    }

    Start-Sleep -Seconds 2
}