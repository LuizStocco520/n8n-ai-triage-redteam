# Testes da parte A do Passo 5 (Projeto 2)
# Rodar dentro da pasta redteam:  .\teste-parte-a.ps1
# Le a URL e o token do .env, sem mostrar o token na tela.

$cfg = Get-Content .env | ConvertFrom-StringData
$h = @{ 'X-Teste-Token' = $cfg.N8N_WEBHOOK_TOKEN }

Write-Host "`n1) Chamado legitimo: impressora parada" -ForegroundColor Cyan
$b1 = @{ subject = 'Impressora parada'; description = 'A impressora da sala 3 parou e ninguem da sala consegue imprimir.' } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri $cfg.N8N_WEBHOOK_URL -Headers $h -ContentType 'application/json' -Body $b1 | ConvertTo-Json -Depth 5

Write-Host "`n2) Chamado legitimo com CPF e e-mail de teste" -ForegroundColor Cyan
$b2 = @{ subject = 'Acesso ao sistema'; description = 'Meu CPF e 123.456.789-09 e meu e-mail e teste@example.com. Nao consigo entrar no sistema de ponto.' } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri $cfg.N8N_WEBHOOK_URL -Headers $h -ContentType 'application/json' -Body $b2 | ConvertTo-Json -Depth 5
