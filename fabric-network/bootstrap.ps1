# Hyperledger Fabric Network Bootstrapper for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "=============================================" -ForegroundColor Green
Write-Host "Bootstrapping Hyperledger Fabric Network..." -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green

# 0. Tear down any running Fabric containers first to release file locks
Write-Host "[0/5] Tearing down existing Fabric containers to release locks..." -ForegroundColor Yellow
if (Test-Path "./docker-compose-fabric.yml") {
    docker compose -f docker-compose-fabric.yml down --volumes --remove-orphans
}

# Ensure system-genesis-block and crypto-config folders don't conflict
if (Test-Path "./crypto-config") {
    Write-Host "Removing existing crypto-config..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "./crypto-config"
}
if (Test-Path "./system-genesis-block") {
    Write-Host "Removing existing system-genesis-block..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "./system-genesis-block"
}
New-Item -ItemType Directory -Path "./system-genesis-block" -Force | Out-Null

# 1. Generate crypto credentials using temporary docker container
Write-Host "[1/5] Generating cryptographic certificates using cryptogen..." -ForegroundColor Cyan
docker run --rm `
  -v "$($PWD.ProviderPath):/opt/gopath/src/github.com/hyperledger/fabric/peer/" `
  -w /opt/gopath/src/github.com/hyperledger/fabric/peer/ `
  hyperledger/fabric-tools:2.5.4 `
  cryptogen generate --config=./crypto-config.yaml

# 2. Generate channel configuration blocks using configtxgen
Write-Host "[2/5] Generating channel genesis block and transaction..." -ForegroundColor Cyan
# Orderer system genesis block
docker run --rm `
  -v "$($PWD.ProviderPath):/opt/gopath/src/github.com/hyperledger/fabric/peer/" `
  -w /opt/gopath/src/github.com/hyperledger/fabric/peer/ `
  -e FABRIC_CFG_PATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/ `
  hyperledger/fabric-tools:2.5.4 `
  configtxgen -profile OneOrgOrdererGenesis -channelID system-channel -outputBlock ./system-genesis-block/genesis.block

# Application channel transaction
docker run --rm `
  -v "$($PWD.ProviderPath):/opt/gopath/src/github.com/hyperledger/fabric/peer/" `
  -w /opt/gopath/src/github.com/hyperledger/fabric/peer/ `
  -e FABRIC_CFG_PATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/ `
  hyperledger/fabric-tools:2.5.4 `
  configtxgen -profile OneOrgChannel -outputCreateChannelTx ./lexledger-channel.tx -channelID lexledger-channel

# 3. Spin up Docker containers
Write-Host "[3/5] Starting Fabric Docker containers..." -ForegroundColor Cyan
docker compose -f docker-compose-fabric.yml up -d

# 4. Wait for Orderer and Peer to boot
Write-Host "Waiting 15 seconds for Orderer and Peer to boot up..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# 5. Create channel and Join Peer
Write-Host "[4/5] Creating channel 'lexledger-channel' and joining peer..." -ForegroundColor Cyan

# Create Channel
docker exec -i cli peer channel create `
  -o orderer.example.com:7050 `
  -c lexledger-channel `
  -f /opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/lexledger-channel.tx `
  --outputBlock /opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/lexledger-channel.block `
  --tls `
  --cafile /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

# Join Channel
docker exec -i cli peer channel join `
  -b /opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/lexledger-channel.block

# 6. Package, Install, Approve, and Commit Go Chaincode
Write-Host "[5/5] Deploying 'clause_cc' Go chaincode..." -ForegroundColor Cyan

# Package Chaincode
docker exec -i cli peer lifecycle chaincode package clause_cc.tar.gz `
  --path /opt/gopath/src/github.com/chaincode/ `
  --lang golang `
  --label clause_cc_1.0

# Install Chaincode
docker exec -i cli peer lifecycle chaincode install clause_cc.tar.gz

# Extract Package ID
Write-Host "Extracting installed Chaincode Package ID..." -ForegroundColor Yellow
$installed = docker exec -i cli peer lifecycle chaincode queryinstalled
Write-Host $installed
$packageId = [regex]::Match($installed, 'clause_cc_1.0:[a-f0-9]+').Value

if (-not $packageId) {
    Write-Error "Failed to retrieve chaincode package ID from peer queryinstalled!"
}
Write-Host "Chaincode Package ID: $packageId" -ForegroundColor Green

# Approve Chaincode Definition
docker exec -i cli peer lifecycle chaincode approveformyorg `
  -o orderer.example.com:7050 `
  --ordererTLSHostnameOverride orderer.example.com `
  --channelID lexledger-channel `
  --name clause_cc `
  --version 1.0 `
  --package-id $packageId `
  --sequence 1 `
  --tls `
  --cafile /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

# Commit Chaincode Definition
docker exec -i cli peer lifecycle chaincode commit `
  -o orderer.example.com:7050 `
  --ordererTLSHostnameOverride orderer.example.com `
  --channelID lexledger-channel `
  --name clause_cc `
  --version 1.0 `
  --sequence 1 `
  --tls `
  --cafile /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

# Wait 5 seconds for chaincode container to launch
Start-Sleep -Seconds 5

# Test Invoke
Write-Host "Running a test invoke..." -ForegroundColor Green
docker exec -i cli peer chaincode invoke `
  -o orderer.example.com:7050 `
  --ordererTLSHostnameOverride orderer.example.com `
  -C lexledger-channel `
  -n clause_cc `
  -c '{"Args":["StoreClause","contract_test","1","test_label","test_text","test_hash"]}' `
  --tls `
  --cafile /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

# Test Query
Write-Host "Running a test query..." -ForegroundColor Green
docker exec -i cli peer chaincode query `
  -C lexledger-channel `
  -n clause_cc `
  -c '{"Args":["GetClause","contract_test","test_label"]}'

Write-Host "=============================================" -ForegroundColor Green
Write-Host "Hyperledger Fabric Network Bootstrap Complete!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
